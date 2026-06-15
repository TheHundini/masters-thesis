package no.softmuffin.bench.tls;

import no.softmuffin.tls.context.PreparedTlsBenchmark;
import no.softmuffin.tls.exchange.TlsLoopbackExchange;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.infra.Blackhole;

import java.security.SecureRandom;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * Measures fresh local TLS connections for classical and PQC/hybrid key exchange.
 *
 * Each invocation opens a new loopback client/server connection. That keeps the
 * benchmark focused on the TLS handshake and, for the message case, confirms
 * that both peers derived working symmetric traffic keys.
 */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Warmup(iterations = 2, time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 8, time = 1, timeUnit = TimeUnit.SECONDS)
@Fork(1)
public class TlsHandshakeBenchmark {

    @State(Scope.Benchmark)
    public static class BenchmarkState {
        @Param({
                "P384-RSA-L1", "P384-ECDSA-L3",
                "MLKEM768-RSA-L1", "X25519-MLKEM768-RSA-L1",
                "P521-ECDSA-L5", "MLKEM1024-RSA-L1", "P384-MLKEM1024-RSA-L1"
        })
        public String handshakeProfile;

        PreparedTlsBenchmark prepared;
        ExecutorService executor;

        /*
         * Provider registration, certificates, and SSLContext creation are setup
         * work. They are prepared once per JMH trial so the measured methods time
         * the connection handshake instead of certificate/key-store construction.
         */
        @Setup(Level.Trial)
        public void setup() throws Exception {
            prepared = TlsLoopbackExchange.prepare(handshakeProfile);
            executor = Executors.newSingleThreadExecutor(command -> {
                final Thread thread = new Thread(command, "tls-benchmark-server");
                thread.setDaemon(true);
                return thread;
            });
        }

        @TearDown(Level.Trial)
        public void tearDown() {
            if (executor != null) {
                executor.shutdownNow();
            }
        }
    }

    @State(Scope.Benchmark)
    public static class MessageState {
        @Param({"32", "1024", "8192"})
        public int messageSizeBytes;

        byte[] message;

        // Use one stable random message per trial. The TLS benchmark measures
        // transport cost, not random byte generation.
        @Setup(Level.Trial)
        public void setup() {
            message = new byte[messageSizeBytes];
            new SecureRandom().nextBytes(message);
        }
    }

    @Benchmark
    public void handshakeOnly(final BenchmarkState state, final Blackhole blackhole) throws Exception {
        blackhole.consume(TlsLoopbackExchange.handshakeOnly(state.prepared, state.executor));
    }

    /*
     * The message benchmark performs the same fresh handshake and then sends one
     * encrypted payload. It is useful as a "real connection" check because the
     * echo would fail if the negotiated traffic keys were not usable.
     */
    @Benchmark
    public void handshakeAndMessage(
            final BenchmarkState state,
            final MessageState messageState,
            final Blackhole blackhole
    ) throws Exception {
        blackhole.consume(TlsLoopbackExchange.handshakeAndMessage(
                state.prepared,
                messageState.message,
                state.executor
        ));
    }
}
