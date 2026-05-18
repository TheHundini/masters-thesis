package no.softmuffin.tls.profile;

import no.softmuffin.tls.context.TlsSecurityProviders;

import java.util.List;
import java.util.Locale;
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
                    "RSA-L3",
                    "TLS 1.3 with RSA-7680 authentication and classical secp384r1 ECDHE key agreement",
                    null,
                    "TLSv1.3",
                    "RSA-L3",
                    List.of("secp384r1"),
                    TLS_13_CIPHER_SUITES
            ),
            TlsBenchmarkProfile.supported(
                    "ECC-L3",
                    "TLS 1.3 with ECDSA P-384 authentication and classical secp384r1 ECDHE key agreement",
                    null,
                    "TLSv1.3",
                    "EC-L3",
                    List.of("secp384r1"),
                    TLS_13_CIPHER_SUITES
            ),
            TlsBenchmarkProfile.supported(
                    "ML-KEM-L3",
                    "TLS 1.3 BCJSSE with ML-KEM-768 key agreement",
                    TlsSecurityProviders.BCJSSE_PROVIDER,
                    "TLSv1.3",
                    "RSA-L3",
                    List.of("MLKEM768"),
                    TLS_13_CIPHER_SUITES
            ),
            TlsBenchmarkProfile.supported(
                    "X25519-ML-KEM-L3",
                    "TLS 1.3 BCJSSE with hybrid X25519 + ML-KEM-768 key agreement",
                    TlsSecurityProviders.BCJSSE_PROVIDER,
                    "TLSv1.3",
                    "RSA-L3",
                    List.of("X25519MLKEM768"),
                    TLS_13_CIPHER_SUITES
            ),
            TlsBenchmarkProfile.supported(
                    "ECC-L5",
                    "TLS 1.3 with ECDSA P-521 authentication and classical secp521r1 ECDHE key agreement",
                    null,
                    "TLSv1.3",
                    "EC-L5",
                    List.of("secp521r1"),
                    TLS_13_CIPHER_SUITES
            ),
            TlsBenchmarkProfile.supported(
                    "ML-KEM-L5",
                    "TLS 1.3 BCJSSE with RSA-7680 authentication and ML-KEM-1024 key agreement",
                    TlsSecurityProviders.BCJSSE_PROVIDER,
                    "TLSv1.3",
                    "RSA-L3",
                    List.of("MLKEM1024"),
                    TLS_13_CIPHER_SUITES
            ),
            TlsBenchmarkProfile.supported(
                    "P384-ML-KEM-L5",
                    "TLS 1.3 BCJSSE with RSA-7680 authentication and hybrid secp384r1 + ML-KEM-1024 key agreement",
                    TlsSecurityProviders.BCJSSE_PROVIDER,
                    "TLSv1.3",
                    "RSA-L3",
                    List.of("SecP384r1MLKEM1024"),
                    TLS_13_CIPHER_SUITES
            ),
            TlsBenchmarkProfile.unsupported(
                    "FrodoKEM",
                    "Bouncy Castle 1.84 provides FrodoKEM primitives, but BCJSSE does not expose a FrodoKEM TLS named group."
            )
    );

    private TlsBenchmarkProfiles() {
    }

    public static List<TlsBenchmarkProfile> all() {
        return PROFILES;
    }

    public static TlsBenchmarkProfile byName(final String profileName) {
        return PROFILES.stream()
                .filter(profile -> profile.name().equalsIgnoreCase(profileName))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unsupported TLS benchmark profile: " + profileName));
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
}
