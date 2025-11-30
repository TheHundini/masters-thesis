package no.softmuffin.config;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

public class JWTDefault {

    private JWTDefault() {
        throw new IllegalStateException("Utility class");
    }

    public static Map<String, Object> defaultClaims(String payload) {
        Map<String, Object> claims = new HashMap<>();
        Instant now = Instant.now();

        claims.put("iss", "softmuffin");
        claims.put("sub", "demo-subject");
        claims.put("iat", now.getEpochSecond());
        claims.put("exp", now.plusSeconds(3600).getEpochSecond());
        claims.put("payload", payload);

        return claims;
    }
}
