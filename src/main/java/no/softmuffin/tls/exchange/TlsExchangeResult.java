package no.softmuffin.tls.exchange;

/**
 * Small result object returned to JMH so the JVM cannot discard the TLS work.
 */
public record TlsExchangeResult(
        String profile,
        TlsSessionInfo client,
        TlsSessionInfo server,
        int applicationBytes
) {
}
