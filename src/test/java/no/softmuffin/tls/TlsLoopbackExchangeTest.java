package no.softmuffin.tls;

import no.softmuffin.tls.context.PreparedTlsBenchmark;
import no.softmuffin.tls.exchange.TlsExchangeResult;
import no.softmuffin.tls.exchange.TlsLoopbackExchange;
import no.softmuffin.tls.profile.TlsBenchmarkProfile;
import no.softmuffin.tls.profile.TlsBenchmarkProfiles;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TlsLoopbackExchangeTest {

    @Test
    @DisplayName("Expose the TLS profiles used by the benchmark suite")
    void exposesBenchmarkProfiles() {
        assertThat(TlsBenchmarkProfiles.all())
                .extracting(TlsBenchmarkProfile::name)
                .containsExactly(
                        "P384-RSA-L1",
                        "P384-ECDSA-L3",
                        "MLKEM768-RSA-L1",
                        "X25519-MLKEM768-RSA-L1",
                        "P521-ECDSA-L5",
                        "MLKEM1024-RSA-L1",
                        "P384-MLKEM1024-RSA-L1",
                        "FrodoKEM"
                );
    }

    @Test
    @DisplayName("Run a full TLS handshake over loopback")
    void runsHandshakeOnly() throws Exception {
        final PreparedTlsBenchmark prepared = TlsLoopbackExchange.prepare("P384-RSA-L1");

        try (ExecutorService executor = Executors.newSingleThreadExecutor()) {
            final TlsExchangeResult result = TlsLoopbackExchange.handshakeOnly(prepared, executor);

            assertThat(result.profile()).isEqualTo("P384-RSA-L1");
            assertThat(result.client().protocol()).isEqualTo("TLSv1.3");
            assertThat(result.client().cipherSuite()).startsWith("TLS_AES_");
            assertThat(result.applicationBytes()).isZero();
        }
    }

    @Test
    @DisplayName("Run TLS key agreement and encrypted application data over loopback")
    void runsHandshakeAndMessage() throws Exception {
        final PreparedTlsBenchmark prepared = TlsLoopbackExchange.prepare("X25519-MLKEM768-RSA-L1");
        final byte[] message = "hello over negotiated TLS keys".getBytes(StandardCharsets.UTF_8);

        try (ExecutorService executor = Executors.newSingleThreadExecutor()) {
            final TlsExchangeResult result = TlsLoopbackExchange.handshakeAndMessage(prepared, message, executor);

            assertThat(result.profile()).isEqualTo("X25519-MLKEM768-RSA-L1");
            assertThat(result.client().protocol()).isEqualTo("TLSv1.3");
            assertThat(result.client().cipherSuite()).startsWith("TLS_");
            assertThat(result.applicationBytes()).isEqualTo(message.length);
        }
    }

    @Test
    @DisplayName("Report FrodoKEM as unavailable for real JSSE TLS handshakes")
    void reportsFrodoKemTlsHandshakeUnavailable() {
        assertThatThrownBy(() -> TlsLoopbackExchange.prepare("FrodoKEM"))
                .isInstanceOf(UnsupportedOperationException.class)
                .hasMessageContaining("BCJSSE does not expose a FrodoKEM TLS named group");

        assertThat(TlsBenchmarkProfiles.runtimeSupport().frodoKemPrimitiveAvailable()).isTrue();
        assertThat(TlsBenchmarkProfiles.runtimeSupport().frodoKemTlsGroupAvailable()).isFalse();
    }
}
