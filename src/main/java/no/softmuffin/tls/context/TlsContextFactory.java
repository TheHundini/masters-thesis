package no.softmuffin.tls.context;

import no.softmuffin.tls.profile.TlsBenchmarkProfile;
import no.softmuffin.tls.profile.TlsBenchmarkProfiles;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

/**
 * Builds the SSL contexts used by the client/server loopback exchange.
 */
public final class TlsContextFactory {

    private static final char[] KEY_PASSWORD = "changeit".toCharArray();

    private TlsContextFactory() {
    }

    public static PreparedTlsBenchmark prepare(final String profileName) throws Exception {
        return prepare(TlsBenchmarkProfiles.byName(profileName));
    }

    public static PreparedTlsBenchmark prepare(final TlsBenchmarkProfile profile) throws Exception {
        TlsSecurityProviders.register();

        if (!profile.supported()) {
            throw new UnsupportedOperationException(profile.unsupportedReason());
        }

        final KeyPair keyPair = TlsCertificateFactory.keyPair(profile.authenticationAlgorithm());
        final X509Certificate certificate = TlsCertificateFactory.selfSignedCertificate(
                keyPair,
                profile.authenticationAlgorithm()
        );

        return new PreparedTlsBenchmark(
                profile,
                serverContext(profile, keyPair, certificate),
                clientContext(profile)
        );
    }

    private static SSLContext serverContext(
            final TlsBenchmarkProfile profile,
            final KeyPair keyPair,
            final X509Certificate certificate
    ) throws Exception {
        final KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore.setKeyEntry("tls-benchmark", keyPair.getPrivate(), KEY_PASSWORD, new X509Certificate[]{certificate});

        final KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keyStore, KEY_PASSWORD);

        final SSLContext context = sslContext(profile);
        context.init(keyManagerFactory.getKeyManagers(), null, new SecureRandom());
        return context;
    }

    private static SSLContext clientContext(final TlsBenchmarkProfile profile) throws Exception {
        final SSLContext context = sslContext(profile);
        context.init(null, trustAllManagers(), new SecureRandom());
        return context;
    }

    private static SSLContext sslContext(final TlsBenchmarkProfile profile) throws Exception {
        if (profile.providerName() == null) {
            return SSLContext.getInstance(profile.protocol());
        }
        return SSLContext.getInstance(profile.protocol(), profile.providerName());
    }

    private static TrustManager[] trustAllManagers() {
        return new TrustManager[]{
                new X509TrustManager() {
                    @Override
                    public void checkClientTrusted(final X509Certificate[] chain, final String authType) {
                    }

                    @Override
                    public void checkServerTrusted(final X509Certificate[] chain, final String authType) {
                    }

                    @Override
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                }
        };
    }
}
