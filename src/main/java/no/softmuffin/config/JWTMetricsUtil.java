package no.softmuffin.config;

import java.util.Base64;

public class JWTMetricsUtil {
    private JWTMetricsUtil() {
        throw new IllegalStateException("Utility class");
    }

    public static int getSignatureByteLength(String jwt) {
        String[] parts = jwt.split("\\.");
        if (parts.length != 3) {
            throw new IllegalArgumentException("Invalid JWT: " + jwt);
        }
        byte[] signature = Base64.getUrlDecoder().decode(parts[2]);
        return signature.length;
    }
}
