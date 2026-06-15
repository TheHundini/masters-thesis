package no.softmuffin.tls.profile;

import no.softmuffin.tls.context.TlsSecurityProviders;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

/**
 * Single source of truth for the TLS profiles used by JMH and tests.
 */
public final class TlsBenchmarkProfiles {

    private static final List<String> TLS_13_CIPHER_SUITES = List.of(
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384"
    );

    private static final List<TlsBenchmarkProfile> PROFILES = List.of(
            TlsBenchmarkProfile.supported(
                    "P384-RSA-L1",
                    "TLS 1.3 with P-384 ECDHE key agreement and RSA-3072 authentication",
                    null,
                    "TLSv1.3",
                    "RSA-L1",
                    List.of("secp384r1"),
                    TLS_13_CIPHER_SUITES
            ),
            TlsBenchmarkProfile.supported(
                    "P384-ECDSA-L3",
                    "TLS 1.3 with P-384 ECDHE key agreement and ECDSA P-384 authentication",
                    null,
                    "TLSv1.3",
                    "EC-L3",
                    List.of("secp384r1"),
                    TLS_13_CIPHER_SUITES
            ),
            TlsBenchmarkProfile.supported(
                    "MLKEM768-RSA-L1",
                    "TLS 1.3 BCJSSE with ML-KEM-768 key agreement and RSA-3072 authentication",
                    TlsSecurityProviders.BCJSSE_PROVIDER,
                    "TLSv1.3",
                    "RSA-L1",
                    List.of("MLKEM768"),
                    TLS_13_CIPHER_SUITES
            ),
            TlsBenchmarkProfile.supported(
                    "X25519-MLKEM768-RSA-L1",
                    "TLS 1.3 BCJSSE with hybrid X25519 + ML-KEM-768 key agreement and RSA-3072 authentication",
                    TlsSecurityProviders.BCJSSE_PROVIDER,
                    "TLSv1.3",
                    "RSA-L1",
                    List.of("X25519MLKEM768"),
                    TLS_13_CIPHER_SUITES
            ),
            TlsBenchmarkProfile.supported(
                    "P521-ECDSA-L5",
                    "TLS 1.3 with P-521 ECDHE key agreement and ECDSA P-521 authentication",
                    null,
                    "TLSv1.3",
                    "EC-L5",
                    List.of("secp521r1"),
                    TLS_13_CIPHER_SUITES
            ),
            TlsBenchmarkProfile.supported(
                    "MLKEM1024-RSA-L1",
                    "TLS 1.3 BCJSSE with ML-KEM-1024 key agreement and RSA-3072 authentication",
                    TlsSecurityProviders.BCJSSE_PROVIDER,
                    "TLSv1.3",
                    "RSA-L1",
                    List.of("MLKEM1024"),
                    TLS_13_CIPHER_SUITES
            ),
            TlsBenchmarkProfile.supported(
                    "P384-MLKEM1024-RSA-L1",
                    "TLS 1.3 BCJSSE with hybrid P-384 + ML-KEM-1024 key agreement and RSA-3072 authentication",
                    TlsSecurityProviders.BCJSSE_PROVIDER,
                    "TLSv1.3",
                    "RSA-L1",
                    List.of("SecP384r1MLKEM1024"),
                    TLS_13_CIPHER_SUITES
            ),
            TlsBenchmarkProfile.unsupported(
                    "FrodoKEM",
                    "Bouncy Castle 1.84 provides FrodoKEM primitives, but BCJSSE does not expose a FrodoKEM TLS named group."
            )
    );

    private static final Map<String, String> LEGACY_PROFILE_NAMES = Map.of(
            "RSA-L1", "P384-RSA-L1",
            "RSA", "P384-RSA-L1",
            "ECC-L3", "P384-ECDSA-L3",
            "ECC", "P384-ECDSA-L3",
            "ML-KEM-L3", "MLKEM768-RSA-L1",
            "ML-KEM", "MLKEM768-RSA-L1",
            "X25519-ML-KEM-L3", "X25519-MLKEM768-RSA-L1",
            "ECC-L5", "P521-ECDSA-L5",
            "ML-KEM-L5", "MLKEM1024-RSA-L1",
            "P384-ML-KEM-L5", "P384-MLKEM1024-RSA-L1"
    );

    private TlsBenchmarkProfiles() {
    }

    public static List<TlsBenchmarkProfile> all() {
        return PROFILES;
    }

    public static TlsBenchmarkProfile byName(final String profileName) {
        final String normalized = normalizeProfileName(profileName);
        return PROFILES.stream()
                .filter(profile -> profile.name().equalsIgnoreCase(normalized))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unsupported TLS benchmark profile: " + normalized));
    }

    public static TlsRuntimeSupport runtimeSupport() {
        TlsSecurityProviders.register();

        final Set<String> configuredGroups = PROFILES.stream()
                .filter(TlsBenchmarkProfile::supported)
                .flatMap(profile -> profile.namedGroups().stream())
                .collect(Collectors.toCollection(TreeSet::new));

        return new TlsRuntimeSupport(
                configuredGroups,
                TlsSecurityProviders.isClassAvailable("org.bouncycastle.pqc.crypto.frodo.FrodoKEMGenerator"),
                configuredGroups.stream().anyMatch(group -> group.toUpperCase(Locale.ROOT).contains("FRODO"))
        );
    }

    private static String normalizeProfileName(final String profileName) {
        final String normalized = profileName.trim().toUpperCase(Locale.ROOT);
        return LEGACY_PROFILE_NAMES.getOrDefault(normalized, normalized);
    }
}
