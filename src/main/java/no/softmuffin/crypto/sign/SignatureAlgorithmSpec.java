package no.softmuffin.crypto.sign;

import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.SLHDSAParameterSpec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.List;
import java.util.Locale;

/**
 * Security-level aware signature parameter set.
 *
 * Labels are the values used by the benchmarks, for example {@code ML-DSA-L3}.
 * The family value is the signer implementation that should handle the label.
 */
public record SignatureAlgorithmSpec(
        String label,
        String family,
        int nistLevel,
        String parameterSet,
        Integer rsaKeyBits,
        String ecCurve,
        AlgorithmParameterSpec pqcParameterSpec
) {

    private static final List<SignatureAlgorithmSpec> SPECS = List.of(
            new SignatureAlgorithmSpec("RSA-L1", "RSA", 1, "RSA-3072", 3072, null, null),
            new SignatureAlgorithmSpec("RSA-L3", "RSA", 3, "RSA-7680", 7680, null, null),
            new SignatureAlgorithmSpec("EC-L3", "EC", 3, "secp384r1", null, "secp384r1", null),
            new SignatureAlgorithmSpec("ML-DSA-L3", "ML-DSA", 3, "ML-DSA-65", null, null, MLDSAParameterSpec.ml_dsa_65),
            new SignatureAlgorithmSpec("SLH-DSA-L3", "SLH-DSA", 3, "SLH-DSA-SHAKE-192s", null, null, SLHDSAParameterSpec.slh_dsa_shake_192s),
            new SignatureAlgorithmSpec("RSA-L5", "RSA", 5, "RSA-15360", 15360, null, null),
            new SignatureAlgorithmSpec("EC-L5", "EC", 5, "secp521r1", null, "secp521r1", null),
            new SignatureAlgorithmSpec("ML-DSA-L5", "ML-DSA", 5, "ML-DSA-87", null, null, MLDSAParameterSpec.ml_dsa_87),
            new SignatureAlgorithmSpec("SLH-DSA-L5", "SLH-DSA", 5, "SLH-DSA-SHAKE-256s", null, null, SLHDSAParameterSpec.slh_dsa_shake_256s)
    );

    public static List<SignatureAlgorithmSpec> all() {
        return SPECS;
    }

    public static List<SignatureAlgorithmSpec> defaultBenchmarkSpecs() {
        return SPECS.stream()
                .filter(spec -> !"RSA-L3".equals(spec.label()))
                .filter(spec -> !"RSA-L5".equals(spec.label()))
                .toList();
    }

    public static List<String> benchmarkLabels() {
        return defaultBenchmarkSpecs().stream()
                .map(SignatureAlgorithmSpec::label)
                .toList();
    }

    public static SignatureAlgorithmSpec byLabel(final String algorithmLabel) {
        final String normalized = normalizeAlias(algorithmLabel);

        return SPECS.stream()
                .filter(spec -> spec.label().equals(normalized))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unsupported algorithm: " + normalized));
    }

    public static String familyFor(final String algorithmLabel) {
        final String normalized = normalizeAlias(algorithmLabel);

        return SPECS.stream()
                .filter(spec -> spec.label().equals(normalized))
                .map(SignatureAlgorithmSpec::family)
                .findFirst()
                .orElse(normalized);
    }

    public static String normalizeAlias(final String algorithmLabel) {
        final String normalized = algorithmLabel.trim().toUpperCase(Locale.ROOT);

        return switch (normalized) {
            case "RSA" -> "RSA-L1";
            case "EC", "ECC" -> "EC-L3";
            case "ML-DSA" -> "ML-DSA-L3";
            case "SLH-DSA" -> "SLH-DSA-L3";
            default -> normalized;
        };
    }
}
