package no.softmuffin.tls;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public final class PostQuantumTlsSupport {

    private static final List<String> POST_QUANTUM_MARKERS = List.of(
            "ML-KEM",
            "MLKEM",
            "KYBER",
            "ML-DSA",
            "MLDSA",
            "SLH-DSA",
            "SLHDSA",
            "FRODO",
            "FRODOKEM",
            "DILITHIUM",
            "SPHINCS"
    );

    private PostQuantumTlsSupport() {
        throw new IllegalStateException("Utility class");
    }

    public static TlsSupportReport inspectCurrentRuntime() {
        try {
            SSLParameters supportedParameters = SSLContext.getDefault().getSupportedSSLParameters();
            return fromCapabilities(
                    Arrays.asList(supportedParameters.getProtocols()),
                    Arrays.asList(supportedParameters.getCipherSuites()),
                    providerAlgorithms()
            );
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Could not inspect TLS support", e);
        }
    }

    static TlsSupportReport fromCapabilities(
            final List<String> protocols,
            final List<String> cipherSuites,
            final Set<String> providerAlgorithms
    ) {
        final List<String> pqSignals = Stream.concat(cipherSuites.stream(), providerAlgorithms.stream())
                .filter(PostQuantumTlsSupport::containsPostQuantumMarker)
                .sorted()
                .toList();

        final boolean tls13Supported = protocols.contains("TLSv1.3");
        final boolean hasPqSignal = !pqSignals.isEmpty();

        return new TlsSupportReport(
                protocols,
                cipherSuites,
                providerAlgorithms,
                pqSignals,
                tls13Supported,
                tls13Supported && hasPqSignal
        );
    }

    private static boolean containsPostQuantumMarker(final String value) {
        final String normalized = value.toUpperCase(Locale.ROOT);
        return POST_QUANTUM_MARKERS.stream().anyMatch(normalized::contains);
    }

    private static Set<String> providerAlgorithms() {
        return Arrays.stream(Security.getProviders())
                .flatMap(PostQuantumTlsSupport::providerServices)
                .collect(Collectors.toCollection(TreeSet::new));
    }

    private static Stream<String> providerServices(final Provider provider) {
        return provider.getServices().stream()
                .map(service -> "%s:%s:%s".formatted(provider.getName(), service.getType(), service.getAlgorithm()));
    }

    public record TlsSupportReport(
            List<String> protocols,
            List<String> cipherSuites,
            Set<String> providerAlgorithms,
            List<String> postQuantumSignals,
            boolean tls13Supported,
            boolean postQuantumTlsLikelyAvailable
    ) {

        public String humanReadableSummary() {
            if (!tls13Supported) {
                return "TLS 1.3 is not available in this runtime.";
            }

            if (postQuantumSignals.isEmpty()) {
                return "TLS 1.3 is available, but no post-quantum TLS algorithm signals were found.";
            }

            return "TLS 1.3 is available and post-quantum algorithm signals were found: %s"
                    .formatted(String.join(", ", postQuantumSignals));
        }
    }
}
