package no.softmuffin.tls.profile;

import java.util.List;

/**
 * Immutable description of one TLS configuration that the benchmark can run.
 */
public record TlsBenchmarkProfile(
        String name,
        String description,
        String providerName,
        String protocol,
        String authenticationAlgorithm,
        List<String> namedGroups,
        List<String> cipherSuites,
        boolean supported,
        String unsupportedReason
) {

    public TlsBenchmarkProfile {
        namedGroups = List.copyOf(namedGroups);
        cipherSuites = List.copyOf(cipherSuites);
    }

    public static TlsBenchmarkProfile supported(
            final String name,
            final String description,
            final String providerName,
            final String protocol,
            final String authenticationAlgorithm,
            final List<String> namedGroups,
            final List<String> cipherSuites
    ) {
        return new TlsBenchmarkProfile(
                name,
                description,
                providerName,
                protocol,
                authenticationAlgorithm,
                namedGroups,
                cipherSuites,
                true,
                ""
        );
    }

    public static TlsBenchmarkProfile unsupported(final String name, final String reason) {
        return new TlsBenchmarkProfile(
                name,
                reason,
                null,
                "",
                "",
                List.of(),
                List.of(),
                false,
                reason
        );
    }

    public String[] namedGroupArray() {
        return namedGroups.toArray(String[]::new);
    }

    public String[] cipherSuiteArray() {
        return cipherSuites.toArray(String[]::new);
    }
}
