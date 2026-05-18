package no.softmuffin.bench.signature;

import no.softmuffin.bench.support.BenchmarkSupport;
import no.softmuffin.crypto.keys.KeyManager;
import no.softmuffin.service.SignatureService;
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
import org.springframework.context.ConfigurableApplicationContext;

import java.security.KeyPair;
import java.util.concurrent.TimeUnit;

/**
 * Measures the complete signature lifecycle with fresh key material.
 *
 * Each benchmark invocation generates a new key pair, signs the payload with
 * that fresh private key, and verifies the JWT with the matching fresh public
 * key. The signer strategies are never mutated with per-invocation keys.
 */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Warmup(iterations = 3, time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 8, time = 1, timeUnit = TimeUnit.SECONDS)
@Fork(2)
public class SignatureFullLifecycleBenchmark {

    @State(Scope.Benchmark)
    public static class BenchmarkState {
        @Param({"RSA-L3", "EC-L3", "ML-DSA-L3", "SLH-DSA-L3", "EC-L5", "ML-DSA-L5", "SLH-DSA-L5"})
        public String algorithm;

        @Param({"32", "256", "1024", "8192"})
        public int payloadSizeBytes;

        ConfigurableApplicationContext context;
        SignatureService signatureService;
        KeyManager keyManager;
        String payload;

        @Setup(Level.Trial)
        public void setup() {
            context = BenchmarkSupport.startContext();
            signatureService = context.getBean(SignatureService.class);
            keyManager = context.getBean(KeyManager.class);
            payload = BenchmarkSupport.payloadOfSize(payloadSizeBytes);
        }

        @TearDown(Level.Trial)
        public void tearDown() {
            if (context != null) {
                context.close();
            }
        }
    }

    @Benchmark
    public void generateSignAndVerify(final BenchmarkState state, final Blackhole blackhole) {
        final KeyPair keyPair = state.keyManager.generateKeyPair(state.algorithm);

        final String token = state.signatureService.generateSignedJwt(
                state.algorithm,
                state.payload,
                keyPair.getPrivate()
        );

        final boolean valid = state.signatureService.verifySignedJwt(
                state.algorithm,
                token,
                keyPair.getPublic()
        );

        if (!valid) {
            throw new IllegalStateException("Generated token did not verify for " + state.algorithm);
        }

        blackhole.consume(keyPair);
        blackhole.consume(token);
        blackhole.consume(valid);
    }
}
