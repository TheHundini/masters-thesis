package no.softmuffin.tls.context;

import no.softmuffin.tls.profile.TlsBenchmarkProfile;

import javax.net.ssl.SSLContext;

/**
 * Expensive TLS setup prepared once per JMH trial, outside the measured method.
 */
public record PreparedTlsBenchmark(
        TlsBenchmarkProfile profile,
        SSLContext serverContext,
        SSLContext clientContext
) {
}
