package no.softmuffin.tls.exchange;

import no.softmuffin.tls.context.PreparedTlsBenchmark;
import no.softmuffin.tls.context.TlsContextFactory;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import java.io.EOFException;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;

/**
 * Runs the measured local TLS flow.
 *
 * Flow:
 * 1. Server socket opens on loopback.
 * 2. Server work runs on the benchmark executor and waits in accept().
 * 3. Client connects, performs TLS handshaking, and optionally sends data.
 * 4. Result records the negotiated session seen by both peers.
 */
public final class TlsLoopbackExchange {

    private TlsLoopbackExchange() {
    }

    public static PreparedTlsBenchmark prepare(final String profileName) throws Exception {
        return TlsContextFactory.prepare(profileName);
    }

    public static TlsExchangeResult handshakeOnly(
            final PreparedTlsBenchmark prepared,
            final ExecutorService executor
    ) throws Exception {
        try (SSLServerSocket serverSocket = TlsSockets.serverSocket(prepared)) {
            final Future<TlsSessionInfo> server = executor.submit(() -> acceptHandshake(serverSocket));

            final TlsSessionInfo client;
            try (SSLSocket clientSocket = TlsSockets.clientSocket(prepared, serverSocket.getLocalPort())) {
                clientSocket.startHandshake();
                client = TlsSessionInfo.from(clientSocket);
                clientSocket.getSession().invalidate();
            }

            return new TlsExchangeResult(prepared.profile().name(), client, server.get(), 0);
        }
    }

    public static TlsExchangeResult handshakeAndMessage(
            final PreparedTlsBenchmark prepared,
            final byte[] message,
            final ExecutorService executor
    ) throws Exception {
        try (SSLServerSocket serverSocket = TlsSockets.serverSocket(prepared)) {
            final Future<TlsSessionInfo> server = executor.submit(() -> echoMessage(serverSocket, message.length));

            final TlsSessionInfo client;
            try (SSLSocket clientSocket = TlsSockets.clientSocket(prepared, serverSocket.getLocalPort())) {
                clientSocket.startHandshake();

                clientSocket.getOutputStream().write(message);
                clientSocket.getOutputStream().flush();

                final byte[] echo = readExactly(clientSocket, message.length);
                if (!Arrays.equals(message, echo)) {
                    throw new IllegalStateException("TLS echo payload changed in transit");
                }

                client = TlsSessionInfo.from(clientSocket);
                clientSocket.getSession().invalidate();
            }

            return new TlsExchangeResult(prepared.profile().name(), client, server.get(), message.length);
        }
    }

    private static TlsSessionInfo acceptHandshake(final SSLServerSocket serverSocket) throws Exception {
        try (SSLSocket socket = (SSLSocket) serverSocket.accept()) {
            socket.startHandshake();
            final TlsSessionInfo session = TlsSessionInfo.from(socket);
            socket.getSession().invalidate();
            return session;
        }
    }

    private static TlsSessionInfo echoMessage(final SSLServerSocket serverSocket, final int messageLength) throws Exception {
        try (SSLSocket socket = (SSLSocket) serverSocket.accept()) {
            socket.startHandshake();

            final byte[] message = readExactly(socket, messageLength);
            socket.getOutputStream().write(message);
            socket.getOutputStream().flush();

            final TlsSessionInfo session = TlsSessionInfo.from(socket);
            socket.getSession().invalidate();
            return session;
        }
    }

    private static byte[] readExactly(final SSLSocket socket, final int length) throws Exception {
        final byte[] bytes = socket.getInputStream().readNBytes(length);
        if (bytes.length != length) {
            throw new EOFException("Expected %d TLS application bytes, got %d".formatted(length, bytes.length));
        }
        return bytes;
    }
}
