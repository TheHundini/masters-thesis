package no.softmuffin.tls.context;

import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Registers the JCA/JSSE providers needed by the benchmark.
 */
public final class TlsSecurityProviders {

    public static final String BC_PROVIDER = BouncyCastleProvider.PROVIDER_NAME;
    public static final String BCJSSE_PROVIDER = "BCJSSE";

    private TlsSecurityProviders() {
    }

    public static void register() {
        disableLogger("org.bouncycastle");
        disableLogger("org.bouncycastle.jsse");
        disableLogger("org.bouncycastle.jsse.provider");

        if (Security.getProvider(BC_PROVIDER) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(BCJSSE_PROVIDER) == null) {
            Security.addProvider(new BouncyCastleJsseProvider(Security.getProvider(BC_PROVIDER)));
        }
    }

    public static boolean isClassAvailable(final String className) {
        try {
            Class.forName(className);
            return true;
        } catch (ClassNotFoundException e) {
            return false;
        }
    }

    private static void disableLogger(final String name) {
        final Logger logger = Logger.getLogger(name);
        logger.setLevel(Level.OFF);
        logger.setUseParentHandlers(false);
    }
}
