package no.softmuffin.bench;

import no.softmuffin.MastersPoCApplication;
import no.softmuffin.service.SignatureService;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;

import java.util.concurrent.TimeUnit;

@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Warmup(iterations = 2, time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 5, time = 1, timeUnit = TimeUnit.SECONDS)
@Fork(1)
public class SignatureServiceBenchmark {

    @State(Scope.Benchmark)
    public static class BenchmarkState {
        @Param({"RSA","ML-DSA","SLH-DSA"})
        public String algorithm;

        ConfigurableApplicationContext context;
        SignatureService signatureService;
        String payload;
        String signedToken;

        @Setup(Level.Trial)
        public void setup() {
            context = new SpringApplicationBuilder(MastersPoCApplication.class)
                    .properties(
                            "spring.main.web-application-type=none",
                            "spring.main.banner-mode=off"
                    )
                    .run();

            signatureService = context.getBean(SignatureService.class);
            payload = "benchmark-payload";
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
    public void verify(BenchmarkState state, Blackhole blackhole) {
        boolean valid = state.signatureService.verifySignedJwt(state.algorithm, state.signedToken);
        blackhole.consume(valid);
    }

    @Benchmark
    public void roundTrip(BenchmarkState state, Blackhole blackhole) {
        String token = state.signatureService.generateSignedJwt(state.algorithm, state.payload);
        boolean valid = state.signatureService.verifySignedJwt(state.algorithm, token);
        blackhole.consume(valid);
    }
}
