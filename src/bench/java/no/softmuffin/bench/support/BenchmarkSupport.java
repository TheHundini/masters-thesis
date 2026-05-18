package no.softmuffin.bench.support;

import no.softmuffin.MastersPoCApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;

/**
 * Shared helpers for JMH benchmarks.
 *
 * JMH benchmark classes should stay focused on the measured operation. Anything
 * that is just setup, such as starting Spring or creating payload data, lives
 * here so it is easy to see what each benchmark is actually timing.
 */
public final class BenchmarkSupport {

    private BenchmarkSupport() {
    }

    public static ConfigurableApplicationContext startContext() {
        return new SpringApplicationBuilder(MastersPoCApplication.class)
                .properties(
                        "spring.main.web-application-type=none",
                        "spring.main.banner-mode=off",
                        "spring.main.log-startup-info=false",
                        "logging.level.root=warn",
                        "logging.level.no.softmuffin=warn"
                )
                .run();
    }

    public static String payloadOfSize(final int payloadSizeBytes) {
        return "x".repeat(payloadSizeBytes);
    }
}
