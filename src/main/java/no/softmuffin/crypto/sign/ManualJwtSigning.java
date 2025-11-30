package no.softmuffin.crypto.sign;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import no.softmuffin.config.JWTDefault;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

@Component
public class ManualJwtSigning implements JwtSigning {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Base64.Encoder B64_ENCODER = Base64.getUrlEncoder().withoutPadding();

    private final PqcSign signatureAlgorithm;

    public ManualJwtSigning(final PqcSign signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    @Override
    public String algorithmId() {
        return signatureAlgorithm.algorithmName();
    }

    @Override
    public String signJwt(final String payload) {
        try {
            String headerB64 = encode(createHeaderClaims());
            String payloadB64 = encode(JWTDefault.defaultClaims(payload));
            String signatureInput = "%s.%s".formatted(headerB64, payloadB64);

            byte[] signature = signatureAlgorithm.sign(signatureInput.getBytes(StandardCharsets.UTF_8));
            String signatureB64 = B64_ENCODER.encodeToString(signature);

            return "%s.%s.%s".formatted(headerB64, payloadB64, signatureB64);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate manual JWT", e);
        }
    }

    private String encode(Map<String, Object> objectMap) throws JsonProcessingException {
        return B64_ENCODER.encodeToString(MAPPER.writeValueAsBytes(objectMap));
    }

    private Map<String, Object> createHeaderClaims() {
        return Map.of(
                "typ", "JWT",
                "alg", signatureAlgorithm.algorithmName()
        );
    }
}
