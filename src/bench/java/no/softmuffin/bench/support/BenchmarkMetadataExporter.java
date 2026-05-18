package no.softmuffin.bench.support;

import no.softmuffin.config.JWTMetricsUtil;
import no.softmuffin.crypto.keys.KeyManager;
import no.softmuffin.crypto.sign.SignatureAlgorithmSpec;
import no.softmuffin.service.SignatureService;
import no.softmuffin.tls.context.TlsCertificateFactory;
import no.softmuffin.tls.context.TlsSecurityProviders;
import no.softmuffin.tls.profile.TlsBenchmarkProfile;
import no.softmuffin.tls.profile.TlsBenchmarkProfiles;
import org.springframework.context.ConfigurableApplicationContext;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Exports size metadata that JMH does not naturally include in its JSON.
 *
 * The benchmark JSON answers timing/allocation questions. This helper adds the
 * other half of the story: key sizes, signature/JWT sizes, and TLS profile
 * sizes that are useful context beside timing results.
 */
public final class BenchmarkMetadataExporter {

    private static final List<Integer> PAYLOAD_SIZES = List.of(32, 256, 1024, 8192);

    private BenchmarkMetadataExporter() {
    }

    public static void main(final String[] args) throws Exception {
        final Path signatureOutputPath = args.length == 0
                ? Path.of("target", "benchmark-signature-size-metadata.csv")
                : Path.of(args[0]);
        final Path tlsOutputPath = args.length < 2
                ? Path.of("target", "benchmark-tls-size-metadata.csv")
                : Path.of(args[1]);

        createParentDirectories(signatureOutputPath);
        createParentDirectories(tlsOutputPath);

        try (ConfigurableApplicationContext context = BenchmarkSupport.startContext()) {
            final KeyManager keyManager = context.getBean(KeyManager.class);
            final SignatureService signatureService = context.getBean(SignatureService.class);

            Files.write(signatureOutputPath, signatureRows(keyManager, signatureService), StandardCharsets.UTF_8);
            Files.write(tlsOutputPath, tlsRows(), StandardCharsets.UTF_8);
        }
    }

    private static List<String> signatureRows(
            final KeyManager keyManager,
            final SignatureService signatureService
    ) {
        final List<String> rows = new ArrayList<>();
        rows.add(String.join(",",
                "algorithm",
                "family",
                "nistLevel",
                "parameterSet",
                "payloadSizeBytes",
                "publicKeyEncodedBits",
                "publicKeyEncodedBytes",
                "privateKeyEncodedBits",
                "privateKeyEncodedBytes",
                "signatureBytes",
                "signatureBase64Chars",
                "tokenBytes",
                "tokenChars"
        ));

        for (SignatureAlgorithmSpec spec : SignatureAlgorithmSpec.defaultBenchmarkSpecs()) {
            final String algorithm = spec.label();
            final KeyPair keyPair = keyManager.getOrCreateKeyPair(algorithm);

            for (int payloadSize : PAYLOAD_SIZES) {
                final String payload = BenchmarkSupport.payloadOfSize(payloadSize);
                final String token = signatureService.generateSignedJwt(algorithm, payload);
                final String signaturePart = token.split("\\.")[2];

                rows.add(String.join(",",
                        csv(algorithm),
                        csv(spec.family()),
                        String.valueOf(spec.nistLevel()),
                        csv(spec.parameterSet()),
                        String.valueOf(payloadSize),
                        String.valueOf(encodedBits(keyPair.getPublic().getEncoded())),
                        String.valueOf(encodedBytes(keyPair.getPublic().getEncoded())),
                        String.valueOf(encodedBits(keyPair.getPrivate().getEncoded())),
                        String.valueOf(encodedBytes(keyPair.getPrivate().getEncoded())),
                        String.valueOf(JWTMetricsUtil.getSignatureByteLength(token)),
                        String.valueOf(signaturePart.length()),
                        String.valueOf(token.getBytes(StandardCharsets.UTF_8).length),
                        String.valueOf(token.length())
                ));
            }
        }

        return rows;
    }

    private static List<String> tlsRows() throws Exception {
        TlsSecurityProviders.register();

        final List<String> rows = new ArrayList<>();
        rows.add(String.join(",",
                "profile",
                "supported",
                "provider",
                "protocol",
                "nistLevel",
                "keyAgreementNistLevel",
                "authenticationNistLevel",
                "effectiveNistLevel",
                "authenticationAlgorithm",
                "authPublicKeyEncodedBytes",
                "authPrivateKeyEncodedBytes",
                "certificateDerBytes",
                "namedGroups",
                "keyAgreement",
                "clientKeyShareBytes",
                "serverKeyShareBytes",
                "sharedSecretMaterialBytes",
                "cipherSuites",
                "unsupportedReason"
        ));

        for (TlsBenchmarkProfile profile : TlsBenchmarkProfiles.all()) {
            if (!profile.supported()) {
                rows.add(String.join(",",
                        csv(profile.name()),
                        "false",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        csv(profile.unsupportedReason())
                ));
                continue;
            }

            final KeyPair keyPair = TlsCertificateFactory.keyPair(profile.authenticationAlgorithm());
            final X509Certificate certificate = TlsCertificateFactory.selfSignedCertificate(
                    keyPair,
                    profile.authenticationAlgorithm()
            );
            final TlsGroupSize groupSize = groupSize(profile.namedGroups());
            final int keyAgreementLevel = groupSize.nistLevel();
            final int authenticationLevel = SignatureAlgorithmSpec.byLabel(profile.authenticationAlgorithm()).nistLevel();
            final int effectiveLevel = effectiveLevel(keyAgreementLevel, authenticationLevel);

            rows.add(String.join(",",
                    csv(profile.name()),
                    "true",
                    csv(provider(profile.providerName())),
                    csv(profile.protocol()),
                    String.valueOf(effectiveLevel),
                    String.valueOf(keyAgreementLevel),
                    String.valueOf(authenticationLevel),
                    String.valueOf(effectiveLevel),
                    csv(profile.authenticationAlgorithm()),
                    String.valueOf(encodedBytes(keyPair.getPublic().getEncoded())),
                    String.valueOf(encodedBytes(keyPair.getPrivate().getEncoded())),
                    String.valueOf(encodedBytes(certificate.getEncoded())),
                    csv(String.join("+", profile.namedGroups())),
                    csv(groupSize.name()),
                    String.valueOf(groupSize.clientKeyShareBytes()),
                    String.valueOf(groupSize.serverKeyShareBytes()),
                    String.valueOf(groupSize.sharedSecretMaterialBytes()),
                    csv(String.join("+", profile.cipherSuites())),
                    ""
            ));
        }

        return rows;
    }

    private static int encodedBytes(final byte[] encoded) {
        if (encoded == null) {
            return 0;
        }
        return encoded.length;
    }

    private static int encodedBits(final byte[] encoded) {
        return encodedBytes(encoded) * 8;
    }

    private static int effectiveLevel(final int keyAgreementLevel, final int authenticationLevel) {
        if (keyAgreementLevel == 0) {
            return authenticationLevel;
        }
        if (authenticationLevel == 0) {
            return keyAgreementLevel;
        }
        return Math.min(keyAgreementLevel, authenticationLevel);
    }

    private static void createParentDirectories(final Path path) throws Exception {
        if (path.getParent() != null) {
            Files.createDirectories(path.getParent());
        }
    }

    private static String provider(final String providerName) {
        if (providerName == null || providerName.isBlank()) {
            return "JDK";
        }
        return providerName;
    }

    private static TlsGroupSize groupSize(final List<String> namedGroups) {
        final String group = namedGroups.isEmpty()
                ? ""
                : namedGroups.getFirst().toUpperCase(Locale.ROOT);

        return switch (group) {
            case "X25519" -> new TlsGroupSize("X25519 ECDHE", 1, 32, 32, 32);
            case "SECP256R1" -> new TlsGroupSize("P-256 ECDHE", 1, 65, 65, 32);
            case "SECP384R1" -> new TlsGroupSize("P-384 ECDHE", 3, 97, 97, 48);
            case "SECP521R1" -> new TlsGroupSize("P-521 ECDHE", 5, 133, 133, 66);
            case "MLKEM768" -> new TlsGroupSize("ML-KEM-768 KEM", 3, 1184, 1088, 32);
            case "X25519MLKEM768" -> new TlsGroupSize("X25519 + ML-KEM-768 hybrid", 3, 1216, 1120, 64);
            case "MLKEM1024" -> new TlsGroupSize("ML-KEM-1024 KEM", 5, 1568, 1568, 32);
            case "SECP384R1MLKEM1024" -> new TlsGroupSize("P-384 + ML-KEM-1024 hybrid", 5, 1665, 1665, 80);
            default -> new TlsGroupSize("unknown", 0, 0, 0, 0);
        };
    }

    private static String csv(final String value) {
        if (value == null) {
            return "";
        }
        final String escaped = value.replace("\"", "\"\"");
        return "\"%s\"".formatted(escaped);
    }

    private record TlsGroupSize(
            String name,
            int nistLevel,
            int clientKeyShareBytes,
            int serverKeyShareBytes,
            int sharedSecretMaterialBytes
    ) {
    }
}
