package no.softmuffin.config;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

public class KeyMetricsUtil {

    private KeyMetricsUtil() {
        throw new IllegalStateException("Utility class");
    }

    public static int publicKeyBits(KeyPair keyPair) {
        PublicKey publicKey = keyPair.getPublic();

        if (publicKey instanceof RSAPublicKey rsaPublicKey) {
            return rsaPublicKey.getModulus().bitLength();
        }

        return publicKey.getEncoded().length * 8;
    }

    public static int privateKeyubits(KeyPair keyPair) {
        PrivateKey privateKey = keyPair.getPrivate();
        // This might be an approximation...
        return privateKey.getEncoded().length * 8;
    }
}
