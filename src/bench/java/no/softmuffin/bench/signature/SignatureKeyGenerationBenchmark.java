package no.softmuffin.bench.signature;

import no.softmuffin.crypto.keys.RunTimeKeyManager;
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
import org.openjdk.jmh.annotations.Warmup;

import java.security.KeyPair;
import java.util.concurrent.TimeUnit;

/**
 * Measures fresh signature key-pair generation.
 *
 * Key generation is separated from sign/verify benchmarks because many
 * post-quantum signature schemes have very different setup costs from their
 * steady-state signing costs.
 */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Warmup(iterations = 3, time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 8, time = 1, timeUnit = TimeUnit.SECONDS)
@Fork(2)
public class SignatureKeyGenerationBenchmark {

    @State(Scope.Benchmark)
    public static class BenchmarkState {
        @Param({"RSA-L1", "EC-L3", "ML-DSA-L3", "SLH-DSA-L3", "EC-L5", "ML-DSA-L5", "SLH-DSA-L5"})
        public String signatureAlgorithm;

        RunTimeKeyManager keyManager;

        // The key manager is cheap to create; the benchmarked method below
        // performs the actual key generation on every invocation.
        @Setup(Level.Trial)
        public void setup() {
            keyManager = new RunTimeKeyManager();
        }
    }

    @Benchmark
    public KeyPair generateSignatureKeyPair(final BenchmarkState state) {
        return state.keyManager.generateKeyPair(state.signatureAlgorithm);
    }
}
