package no.softmuffin.crypto.sign;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import no.softmuffin.config.JWTDefault;

import java.nio.charset.StandardCharsets;
import java.util.Base64.Decoder;
import java.util.Base64;
import java.util.Map;

public class ManualJwtSigning implements JwtSigning {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Base64.Encoder B64_ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Decoder B64_DECODER = Base64.getUrlDecoder();

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
            String signatureInput = createSignatureInput(headerB64, payloadB64);

            byte[] signature = signatureAlgorithm.sign(signatureInput.getBytes(StandardCharsets.UTF_8));
            String signatureB64 = B64_ENCODER.encodeToString(signature);

            return "%s.%s.%s".formatted(headerB64, payloadB64, signatureB64);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate manual JWT", e);
        }
    }

    @Override
    public boolean verifyJwt(final String jwt) {
        try {
            final String[] parts = jwt.split("\\.");
            if (parts.length != 3) {
                return false;
            }

            final Map<?, ?> header = MAPPER.readValue(B64_DECODER.decode(parts[0]), Map.class);
            final Object algorithm = header.get("alg");
            if (!signatureAlgorithm.algorithmName().equals(algorithm)) {
                return false;
            }

            final String signatureInput = createSignatureInput(parts[0], parts[1]);
            final byte[] signature = B64_DECODER.decode(parts[2]);

            return signatureAlgorithm.verify(signatureInput.getBytes(StandardCharsets.UTF_8), signature);
        } catch (Exception e) {
            return false;
        }
    }

    private String encode(Map<String, Object> objectMap) throws JsonProcessingException {
        return B64_ENCODER.encodeToString(MAPPER.writeValueAsBytes(objectMap));
    }

    private String createSignatureInput(final String headerB64, final String payloadB64) {
        return "%s.%s".formatted(headerB64, payloadB64);
    }

    private Map<String, Object> createHeaderClaims() {
        return Map.of(
                "typ", "JWT",
                "alg", signatureAlgorithm.algorithmName()
        );
    }
}
