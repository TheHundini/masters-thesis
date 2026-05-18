package no.softmuffin.tls;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class PostQuantumTlsSupportTest {

    @Test
    @DisplayName("Report likely PQ TLS support when TLS 1.3 and PQ signals are present")
    void reportsLikelyPostQuantumTlsSupport() {
        final PostQuantumTlsSupport.TlsSupportReport report = PostQuantumTlsSupport.fromCapabilities(
                List.of("TLSv1.2", "TLSv1.3"),
                List.of("TLS_AES_128_GCM_SHA256"),
                Set.of("BC:KeyAgreement:ML-KEM", "BC:Signature:ML-DSA")
        );

        assertThat(report.tls13Supported()).isTrue();
        assertThat(report.postQuantumTlsLikelyAvailable()).isTrue();
        assertThat(report.postQuantumSignals()).containsExactly("BC:KeyAgreement:ML-KEM", "BC:Signature:ML-DSA");
        assertThat(report.humanReadableSummary()).contains("post-quantum algorithm signals");
    }

    @Test
    @DisplayName("Do not claim PQ TLS support from TLS 1.3 alone")
    void tls13AloneIsNotEnoughForPostQuantumTls() {
        final PostQuantumTlsSupport.TlsSupportReport report = PostQuantumTlsSupport.fromCapabilities(
                List.of("TLSv1.3"),
                List.of("TLS_AES_128_GCM_SHA256"),
                Set.of("SunEC:Signature:SHA256withECDSA")
        );

        assertThat(report.tls13Supported()).isTrue();
        assertThat(report.postQuantumTlsLikelyAvailable()).isFalse();
        assertThat(report.postQuantumSignals()).isEmpty();
        assertThat(report.humanReadableSummary()).isEqualTo(
                "TLS 1.3 is available, but no post-quantum TLS algorithm signals were found."
        );
    }

    @Test
    @DisplayName("Inspect the current JVM without failing")
    void inspectCurrentRuntime() {
        final PostQuantumTlsSupport.TlsSupportReport report = PostQuantumTlsSupport.inspectCurrentRuntime();

        assertThat(report.protocols()).isNotEmpty();
        assertThat(report.cipherSuites()).isNotEmpty();
        assertThat(report.providerAlgorithms()).isNotEmpty();
        assertThat(report.humanReadableSummary()).isNotBlank();
    }
}
