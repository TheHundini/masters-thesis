package no.softmuffin.crypto.sign;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import no.softmuffin.config.JWTDefault;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
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
        return signJwt(payload, signatureAlgorithm::sign);
    }

    @Override
    public String signJwt(final String payload, final PrivateKey privateKey) {
        return signJwt(payload, message -> signatureAlgorithm.sign(message, privateKey));
    }

    private String signJwt(final String payload, final MessageSigner signer) {
        try {
            final String signatureInput = createSigningInput(payload);
            final byte[] signature = signer.sign(signatureInput.getBytes(StandardCharsets.UTF_8));
            return createJwt(signatureInput, signature);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate manual JWT", e);
        }
    }

    @Override
    public boolean verifyJwt(final String jwt) {
        return verifyJwt(jwt, signatureAlgorithm::verify);
    }

    @Override
    public boolean verifyJwt(final String jwt, final PublicKey publicKey) {
        return verifyJwt(jwt, (message, signature) -> signatureAlgorithm.verify(message, signature, publicKey));
    }

    private boolean verifyJwt(final String jwt, final MessageVerifier verifier) {
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

            return verifier.verify(signatureInput.getBytes(StandardCharsets.UTF_8), signature);
        } catch (Exception e) {
            return false;
        }
    }

    private String encode(Map<String, Object> objectMap) throws JsonProcessingException {
        return B64_ENCODER.encodeToString(MAPPER.writeValueAsBytes(objectMap));
    }

    private String createSigningInput(final String payload) throws JsonProcessingException {
        final String headerB64 = encode(createHeaderClaims());
        final String payloadB64 = encode(JWTDefault.defaultClaims(payload));
        return createSignatureInput(headerB64, payloadB64);
    }

    private String createSignatureInput(final String headerB64, final String payloadB64) {
        return "%s.%s".formatted(headerB64, payloadB64);
    }

    private String createJwt(final String signatureInput, final byte[] signature) {
        return "%s.%s".formatted(signatureInput, B64_ENCODER.encodeToString(signature));
    }

    private Map<String, Object> createHeaderClaims() {
        return Map.of(
                "typ", "JWT",
                "alg", signatureAlgorithm.algorithmName()
        );
    }

    @FunctionalInterface
    private interface MessageSigner {
        byte[] sign(byte[] message);
    }

    @FunctionalInterface
    private interface MessageVerifier {
        boolean verify(byte[] message, byte[] signature);
    }
}
