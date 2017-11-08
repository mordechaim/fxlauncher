package fxlauncher;

import javafx.application.Application;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.xml.bind.JAXB;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.URI;
import java.net.URL;
import java.net.URLClassLoader;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.logging.FileHandler;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;
import java.util.stream.Collectors;

@SuppressWarnings("unchecked")
public abstract class AbstractLauncher<APP> {
	private static final Logger log = Logger.getLogger("AbstractLauncher");

	protected FXManifest manifest;
	private String phase;

	/**
	 * Make java.util.logger log to a file. Default it will log to
	 * $TMPDIR/fxlauncher.log. This can be overriden by using comman line parameter
	 * <code>--logfile=logfile</code>
	 *
	 * @throws IOException
	 */
	protected void setupLogFile() throws IOException {
		String filename = System.getProperty("java.io.tmpdir") + File.separator + "fxlauncher.log";
		if (getParameters().getNamed().containsKey("logfile"))
			filename = getParameters().getNamed().get("logfile");
		System.out.println("logging to " + filename);
		FileHandler handler = new FileHandler(filename);
		handler.setFormatter(new SimpleFormatter());
		log.addHandler(handler);
	}

	/**
	 * Check if the SSL connection needs to ignore the validity of the ssl
	 * certificate.
	 *
	 * @throws KeyManagementException
	 * @throws NoSuchAlgorithmException
	 */
	protected void checkSSLIgnoreflag() throws KeyManagementException, NoSuchAlgorithmException {
		if (getParameters().getUnnamed().contains("--ignoressl")) {
			setupIgnoreSSLCertificate();
		}
	}

	protected ClassLoader createClassLoader(Path cacheDir) {
		List<URL> libs = manifest.files.stream().filter(LibraryFile::loadForCurrentPlatform)
				.map(it -> it.toURL(cacheDir)).collect(Collectors.toList());

		ClassLoader systemClassLoader = ClassLoader.getSystemClassLoader();
		if (systemClassLoader instanceof FxlauncherClassLoader) {
			((FxlauncherClassLoader) systemClassLoader).addUrls(libs);
			return systemClassLoader;
		} else {
			ClassLoader classLoader = new URLClassLoader(libs.toArray(new URL[libs.size()]));
			Thread.currentThread().setContextClassLoader(classLoader);

			setupClassLoader(classLoader);

			return classLoader;
		}
	}

	protected void updateManifest() throws Exception {
		phase = "Update Manifest";
		syncManifest();
	}

	/**
	 * Check if remote files are newer then local files. Return true if files are
	 * updated, triggering the whatsnew option else false. Also return false and do
	 * not check for updates if the <code>--offline</code> commandline argument is
	 * set.
	 *
	 * @return true if new files have been downloaded, false otherwise.
	 * @throws Exception
	 */
	protected boolean syncFiles() throws Exception {

		Path cacheDir = manifest.resolveCacheDir(getParameters().getNamed());
		log.info(String.format("Using cache dir %s", cacheDir));

		phase = "File Synchronization";

		if (getParameters().getUnnamed().contains("--offline")) {
			log.info("not updating files from remote, offline selected");
			return false; // to signal that nothing has changed.
		}
		List<LibraryFile> needsUpdate = manifest.files.stream().filter(LibraryFile::loadForCurrentPlatform)
				.filter(it -> it.needsUpdate(cacheDir)).collect(Collectors.toList());

		if (needsUpdate.isEmpty())
			return false;

		Signature sig = null;
		if (getParameters().getNamed().containsKey("cert")) {
			String certPath = getParameters().getNamed().get("cert");

			try (InputStream certIn = Files.newInputStream(Paths.get(certPath))) {
				Certificate cert = CertificateFactory.getInstance("X.509").generateCertificate(certIn);
				sig = Signature.getInstance("SHA256with" + cert.getPublicKey().getAlgorithm());
				sig.initVerify(cert);
			}
		}

		long totalBytes = needsUpdate.stream().mapToLong(f -> f.size).sum();
		long totalWritten = 0L;

		for (LibraryFile lib : needsUpdate) {
			Path target = cacheDir.resolve(lib.file).toAbsolutePath();
			Path temp = cacheDir.resolve("~" + lib.file + ".tmp");
			Files.createDirectories(target.getParent());

			try (InputStream input = openDownloadStream(lib.uri); OutputStream output = Files.newOutputStream(temp)) {

				byte[] buf = new byte[65536];

				int read;
				while ((read = input.read(buf)) > -1) {
					output.write(buf, 0, read);

					if (sig != null) {
						sig.update(buf, 0, read);
					}

					totalWritten += read;
					double progress = (double) totalWritten / totalBytes;
					updateProgress(progress);
				}

				if (sig != null) {
					if (lib.signature == null)
						throw new SecurityException("No signature in manifest.");

					byte[] sigData = Base64.getDecoder().decode(lib.signature);
					if (!sig.verify(sigData))
						throw new SecurityException("Signature verification failed.");
				}

				Files.move(temp, target, StandardCopyOption.REPLACE_EXISTING);
			} finally {
				Files.deleteIfExists(temp);
			}
		}
		return true;
	}

	private InputStream openDownloadStream(URI uri) throws IOException {
		if (uri.getScheme().equals("file"))
			return Files.newInputStream(new File(uri.getPath()).toPath());

		URLConnection connection = uri.toURL().openConnection();
		if (uri.getUserInfo() != null) {
			byte[] payload = uri.getUserInfo().getBytes(StandardCharsets.UTF_8);
			String encoded = Base64.getEncoder().encodeToString(payload);
			connection.setRequestProperty("Authorization", String.format("Basic %s", encoded));
		}
		return connection.getInputStream();
	}

	protected void createApplicationEnvironment() throws Exception {
		phase = "Create Application";

		if (manifest == null)
			throw new IllegalArgumentException("Unable to retrieve embedded or remote manifest.");
		List<String> preloadLibs = manifest.getPreloadNativeLibraryList();
		for (String preloadLib : preloadLibs)
			System.loadLibrary(preloadLib);

		Path cacheDir = manifest.resolveCacheDir(getParameters() != null ? getParameters().getNamed() : null);

		ClassLoader classLoader = createClassLoader(cacheDir);
		Class<APP> appclass = (Class<APP>) classLoader.loadClass(manifest.launchClass);

		createApplication(appclass);
	}

	protected void syncManifest() throws Exception {
		Map<String, String> namedParams = getParameters().getNamed();

		URI remote = null;
		Path local = null;

		FXManifest man = null;

		if (namedParams.containsKey("remote")) {
			try {
				remote = URI.create(namedParams.get("remote"));
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

		if (namedParams.containsKey("local")) {
			local = Paths.get(namedParams.get("local")).toAbsolutePath();
			Files.createDirectories(local.getParent());
		}

		if (remote != null) {
			try {
				man = FXManifest.load(remote);

				if (getParameters().getUnnamed().contains("--syncLocal")) {
					try (PrintWriter out = new PrintWriter(Files.newBufferedWriter(local))) {
						out.print(man);
					}
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
		} else if (local != null) {
			try {
				man = FXManifest.load(local.toUri());
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

		if(man == null) {
			URL embedded = getClass().getResource("/app.xml");
			if(embedded != null) {
				try {
					man = JAXB.unmarshal(embedded, FXManifest.class);
				}catch (Exception e) {
					e.printStackTrace();
				}
			}
		}

		if(man == null) {
			throw new IOException("Could not load manifest.");
		}

		manifest = man;
	}

	protected void setupIgnoreSSLCertificate() throws NoSuchAlgorithmException, KeyManagementException {
		log.info("starting ssl setup");
		TrustManager[] trustManager = new TrustManager[] { new X509TrustManager() {
			@Override
			public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
			}

			@Override
			public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {

			}

			@Override
			public X509Certificate[] getAcceptedIssuers() {
				return null;
			}
		} };
		SSLContext sslContext = SSLContext.getInstance("SSL");
		sslContext.init(null, trustManager, new java.security.SecureRandom());
		HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());

		HostnameVerifier hostnameVerifier = (s, sslSession) -> true;
		HttpsURLConnection.setDefaultHostnameVerifier(hostnameVerifier);
	}

	protected boolean checkIgnoreUpdateErrorSetting() {
		return getParameters().getUnnamed().contains("--stopOnUpdateErrors");
	}

	public String getPhase() {
		return phase;
	}

	public void setPhase(String phase) {
		this.phase = phase;
	}

	public FXManifest getManifest() {
		return manifest;
	}

	protected abstract Application.Parameters getParameters();

	protected abstract void updateProgress(double progress);

	protected abstract void createApplication(Class<APP> appClass);

	protected abstract void reportError(String title, Throwable error);

	protected abstract void setupClassLoader(ClassLoader classLoader);
}
