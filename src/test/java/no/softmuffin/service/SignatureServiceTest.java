package no.softmuffin.service;

import no.softmuffin.crypto.sign.JwtSigning;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SignatureServiceTest {

    private final SignatureService service = new SignatureService(List.of(
            new StubJwtSigning("RSA"),
            new StubJwtSigning("ML-DSA")
    ));

    @Test
    @DisplayName("Find strategies with trimmed, case-insensitive algorithm labels")
    void findsStrategyByNormalizedAlgorithmLabel() {
        final String token = service.generateSignedJwt(" ml-dsa ", "payload");

        assertThat(token).isEqualTo("ML-DSA.payload.token");
        assertThat(service.verifySignedJwt("ML-DSA", token)).isTrue();
    }

    @Test
    @DisplayName("Reject unknown algorithm labels clearly")
    void rejectsUnknownAlgorithm() {
        assertThatThrownBy(() -> service.generateSignedJwt("unknown", "payload"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Unsupported algorithm: UNKNOWN");
    }

    private record StubJwtSigning(String algorithmId) implements JwtSigning {

        @Override
        public String signJwt(final String payload) {
            return "%s.%s.token".formatted(algorithmId, payload);
        }

        @Override
        public boolean verifyJwt(final String jwt) {
            return jwt.startsWith(algorithmId + ".");
        }

        @Override
        public String signJwt(final String payload, final PrivateKey privateKey) {
            return signJwt(payload);
        }

        @Override
        public boolean verifyJwt(final String jwt, final PublicKey publicKey) {
            return verifyJwt(jwt);
        }
    }
}
