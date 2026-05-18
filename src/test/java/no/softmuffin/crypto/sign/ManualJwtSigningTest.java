package no.softmuffin.crypto.sign;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class ManualJwtSigningTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final TypeReference<Map<String, Object>> JSON_OBJECT = new TypeReference<>() {
    };
    private static final Base64.Decoder B64_DECODER = Base64.getUrlDecoder();
    private static final Base64.Encoder B64_ENCODER = Base64.getUrlEncoder().withoutPadding();

    private final ManualJwtSigning signer = new ManualJwtSigning(new DigestPqcSign("TEST-PQC"));

    @Test
    @DisplayName("Create a three-part JWT with the PQC algorithm in the header")
    void signCreatesReadableJwtShape() throws Exception {
        final String token = signer.signJwt("hello");
        final String[] parts = token.split("\\.");

        assertThat(parts).hasSize(3);
        assertThat(parts[0]).doesNotContain("=");
        assertThat(parts[1]).doesNotContain("=");
        assertThat(parts[2]).doesNotContain("=");

        final Map<String, Object> header = MAPPER.readValue(B64_DECODER.decode(parts[0]), JSON_OBJECT);
        final Map<String, Object> payload = MAPPER.readValue(B64_DECODER.decode(parts[1]), JSON_OBJECT);

        assertThat(header).containsEntry("typ", "JWT");
        assertThat(header).containsEntry("alg", "TEST-PQC");
        assertThat(payload).containsEntry("payload", "hello");
    }

    @Test
    @DisplayName("Verify a token created by the same PQC signer")
    void verifyAcceptsOwnToken() {
        final String token = signer.signJwt("round-trip");

        assertThat(signer.verifyJwt(token)).isTrue();
    }

    @Test
    @DisplayName("Reject a token whose payload was changed after signing")
    void verifyRejectsTamperedPayload() throws Exception {
        final String token = signer.signJwt("original");
        final String[] parts = token.split("\\.");
        final String changedPayload = B64_ENCODER.encodeToString(
                MAPPER.writeValueAsBytes(Map.of("payload", "changed"))
        );

        final String tamperedToken = "%s.%s.%s".formatted(parts[0], changedPayload, parts[2]);

        assertThat(signer.verifyJwt(tamperedToken)).isFalse();
    }

    @Test
    @DisplayName("Reject malformed JWT input instead of throwing")
    void verifyRejectsMalformedToken() {
        assertThat(signer.verifyJwt("not-a-jwt")).isFalse();
    }

    @Test
    @DisplayName("Sign and verify a manual JWT with explicitly supplied key material")
    void keyAwareSigningUsesProvidedKeys() {
        final ManualJwtSigning keyAwareSigner = new ManualJwtSigning(new DigestPqcSign("KEY-AWARE"));
        final byte[] sharedKeyBytes = "fresh-key".getBytes(StandardCharsets.UTF_8);
        final PrivateKey privateKey = new TestPrivateKey(sharedKeyBytes);
        final PublicKey publicKey = new TestPublicKey(sharedKeyBytes);
        final PublicKey wrongPublicKey = new TestPublicKey("wrong-key".getBytes(StandardCharsets.UTF_8));

        final String token = keyAwareSigner.signJwt("fresh-payload", privateKey);

        assertThat(keyAwareSigner.verifyJwt(token, publicKey)).isTrue();
        assertThat(keyAwareSigner.verifyJwt(token, wrongPublicKey)).isFalse();
    }

    private record DigestPqcSign(String algorithmName) implements PqcSign {

        private static final byte[] DEFAULT_KEY = "default-key".getBytes(StandardCharsets.UTF_8);

        @Override
        public byte[] sign(final byte[] data) {
            return digest(DEFAULT_KEY, data);
        }

        @Override
        public boolean verify(final byte[] data, final byte[] signature) {
            return MessageDigest.isEqual(digest(DEFAULT_KEY, data), signature);
        }

        @Override
        public byte[] sign(final byte[] message, final PrivateKey privateKey) {
            return digest(privateKey.getEncoded(), message);
        }

        @Override
        public boolean verify(final byte[] message, final byte[] signature, final PublicKey publicKey) {
            return MessageDigest.isEqual(digest(publicKey.getEncoded(), message), signature);
        }

        private byte[] digest(final byte[] key, final byte[] data) {
            try {
                final MessageDigest digest = MessageDigest.getInstance("SHA-256");
                digest.update(algorithmName.getBytes(StandardCharsets.UTF_8));
                digest.update(key);
                return digest.digest(data);
            } catch (Exception e) {
                throw new IllegalStateException("Could not create test signature", e);
            }
        }
    }

    private record TestPrivateKey(byte[] encoded) implements PrivateKey {

        @Override
        public String getAlgorithm() {
            return "TEST";
        }

        @Override
        public String getFormat() {
            return "RAW";
        }

        @Override
        public byte[] getEncoded() {
            return encoded.clone();
        }
    }

    private record TestPublicKey(byte[] encoded) implements PublicKey {

        @Override
        public String getAlgorithm() {
            return "TEST";
        }

        @Override
        public String getFormat() {
            return "RAW";
        }

        @Override
        public byte[] getEncoded() {
            return encoded.clone();
        }
    }
}
