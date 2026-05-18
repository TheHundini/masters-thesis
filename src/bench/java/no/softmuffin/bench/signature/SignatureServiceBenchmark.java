package no.softmuffin.bench.signature;

import no.softmuffin.bench.support.BenchmarkSupport;
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

import java.util.concurrent.TimeUnit;

/**
 * Measures signing and verification with keys prepared by the application.
 *
 * This benchmark answers: "How expensive is a normal sign/verify operation
 * after the algorithm has already been configured and its key material exists?"
 */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Warmup(iterations = 3, time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 8, time = 1, timeUnit = TimeUnit.SECONDS)
@Fork(2)
public class SignatureServiceBenchmark {

    @State(Scope.Benchmark)
    public static class BenchmarkState {
        @Param({"RSA-L3", "EC-L3", "ML-DSA-L3", "SLH-DSA-L3", "EC-L5", "ML-DSA-L5", "SLH-DSA-L5"})
        public String algorithm;

        @Param({"32", "256", "1024", "8192"})
        public int payloadSizeBytes;

        ConfigurableApplicationContext context;
        SignatureService signatureService;
        String payload;
        String signedToken;

        /*
         * Trial setup is intentionally outside the measured methods. The
         * separate SignatureKeyGenerationBenchmark measures uncached key
         * generation, so this class only measures JWT signing and verification.
         */
        @Setup(Level.Trial)
        public void setup() {
            context = BenchmarkSupport.startContext();
            signatureService = context.getBean(SignatureService.class);
            payload = BenchmarkSupport.payloadOfSize(payloadSizeBytes);
            signedToken = signatureService.generateSignedJwt(algorithm, payload);
        }

        @TearDown(Level.Trial)
        public void tearDown() {
            if (context != null) {
                context.close();
            }
        }
    }

    @Benchmark
    public String sign(final BenchmarkState state) {
        return state.signatureService.generateSignedJwt(state.algorithm, state.payload);
    }

    @Benchmark
    public void verify(final BenchmarkState state, final Blackhole blackhole) {
        final boolean valid = state.signatureService.verifySignedJwt(state.algorithm, state.signedToken);
        if (!valid) {
            throw new IllegalStateException("Token did not verify for " + state.algorithm);
        }
        blackhole.consume(valid);
    }

    @Benchmark
    public void roundTrip(final BenchmarkState state, final Blackhole blackhole) {
        final String token = state.signatureService.generateSignedJwt(state.algorithm, state.payload);
        final boolean valid = state.signatureService.verifySignedJwt(state.algorithm, token);
        if (!valid) {
            throw new IllegalStateException("Token did not verify for " + state.algorithm);
        }
        blackhole.consume(token);
        blackhole.consume(valid);
    }
}
