package no.softmuffin.tls.exchange;

import javax.net.ssl.SSLSocket;

/**
 * The negotiated session details that are useful to assert in tests.
 */
public record TlsSessionInfo(
        String protocol,
        String cipherSuite
) {

    static TlsSessionInfo from(final SSLSocket socket) {
        return new TlsSessionInfo(
                socket.getSession().getProtocol(),
                socket.getSession().getCipherSuite()
        );
    }
}
