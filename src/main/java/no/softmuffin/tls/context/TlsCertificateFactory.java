package no.softmuffin.tls.context;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import no.softmuffin.crypto.sign.SignatureAlgorithmSpec;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Date;

/**
 * Creates short-lived self-signed certificates for local TLS benchmarks.
 */
public final class TlsCertificateFactory {

    private TlsCertificateFactory() {
    }

    public static KeyPair keyPair(final String algorithm) throws Exception {
        final SignatureAlgorithmSpec spec = SignatureAlgorithmSpec.byLabel(algorithm);
        return switch (spec.family()) {
            case "RSA" -> {
                final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
                generator.initialize(spec.rsaKeyBits());
                yield generator.generateKeyPair();
            }
            case "EC" -> {
                final KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
                generator.initialize(new ECGenParameterSpec(spec.ecCurve()));
                yield generator.generateKeyPair();
            }
            default -> throw new IllegalArgumentException("Unsupported TLS authentication algorithm: " + algorithm);
        };
    }

    public static X509Certificate selfSignedCertificate(final KeyPair keyPair, final String algorithm) throws Exception {
        final Instant now = Instant.now();
        final X500Name subject = new X500Name("CN=localhost");
        final JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject,
                BigInteger.valueOf(now.toEpochMilli()),
                Date.from(now.minusSeconds(60)),
                Date.from(now.plusSeconds(3600)),
                subject,
                keyPair.getPublic()
        );

        final ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm(algorithm))
                .setProvider(TlsSecurityProviders.BC_PROVIDER)
                .build(keyPair.getPrivate());
        final X509CertificateHolder holder = builder.build(signer);

        return new JcaX509CertificateConverter()
                .setProvider(TlsSecurityProviders.BC_PROVIDER)
                .getCertificate(holder);
    }

    private static String signatureAlgorithm(final String authenticationAlgorithm) {
        final SignatureAlgorithmSpec spec = SignatureAlgorithmSpec.byLabel(authenticationAlgorithm);
        return switch (spec.family()) {
            case "RSA" -> spec.nistLevel() >= 5 ? "SHA512withRSA" : "SHA384withRSA";
            case "EC" -> spec.nistLevel() >= 5 ? "SHA512withECDSA" : "SHA384withECDSA";
            default -> throw new IllegalArgumentException("Unsupported TLS authentication algorithm: " + authenticationAlgorithm);
        };
    }
}
