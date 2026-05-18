package no.softmuffin.tls.exchange;

import no.softmuffin.tls.context.PreparedTlsBenchmark;
import no.softmuffin.tls.profile.TlsBenchmarkProfile;

import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import java.net.InetAddress;

/**
 * Keeps all JSSE socket configuration in one place.
 */
final class TlsSockets {

    private TlsSockets() {
    }

    static SSLServerSocket serverSocket(final PreparedTlsBenchmark prepared) throws Exception {
        final TlsBenchmarkProfile profile = prepared.profile();
        final ServerSocketFactory socketFactory = prepared.serverContext().getServerSocketFactory();
        final SSLServerSocket socket = (SSLServerSocket) socketFactory.createServerSocket(
                0,
                1,
                InetAddress.getLoopbackAddress()
        );

        socket.setNeedClientAuth(false);
        configure(socket, profile);
        return socket;
    }

    static SSLSocket clientSocket(final PreparedTlsBenchmark prepared, final int port) throws Exception {
        final SSLSocket socket = (SSLSocket) prepared.clientContext().getSocketFactory().createSocket(
                InetAddress.getLoopbackAddress(),
                port
        );

        configure(socket, prepared.profile());
        return socket;
    }

    private static void configure(final SSLServerSocket socket, final TlsBenchmarkProfile profile) {
        socket.setEnabledProtocols(new String[]{profile.protocol()});
        socket.setEnabledCipherSuites(profile.cipherSuiteArray());
        applyNamedGroups(socket.getSSLParameters(), profile, socket::setSSLParameters);
    }

    private static void configure(final SSLSocket socket, final TlsBenchmarkProfile profile) {
        socket.setEnabledProtocols(new String[]{profile.protocol()});
        socket.setEnabledCipherSuites(profile.cipherSuiteArray());
        applyNamedGroups(socket.getSSLParameters(), profile, socket::setSSLParameters);
    }

    private static void applyNamedGroups(
            final SSLParameters parameters,
            final TlsBenchmarkProfile profile,
            final SslParametersSetter setter
    ) {
        if (!profile.namedGroups().isEmpty()) {
            parameters.setNamedGroups(profile.namedGroupArray());
            setter.setSSLParameters(parameters);
        }
    }

    @FunctionalInterface
    private interface SslParametersSetter {
        void setSSLParameters(SSLParameters parameters);
    }
}
