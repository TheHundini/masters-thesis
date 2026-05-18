package no.softmuffin.service;

import no.softmuffin.api.dto.BenchmarkResultDto;
import no.softmuffin.crypto.keys.KeyManager;
import no.softmuffin.crypto.sign.JwtSigning;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SignatureBenchmarkServiceTest {

    private final SignatureBenchmarkService benchmarkService = new SignatureBenchmarkService(
            new SignatureService(List.of(new BenchmarkJwtSigning())),
            new RsaOnlyKeyManager()
    );

    @Test
    @DisplayName("Return benchmark metrics for a valid signing run")
    void returnsMetricsForValidRun() {
        final BenchmarkResultDto result = benchmarkService.runSignatureBenchmark("TEST", 3, "payload");

        assertThat(result.algorithm()).isEqualTo("TEST");
        assertThat(result.iterations()).isEqualTo(3);
        assertThat(result.totalSignMs()).isGreaterThanOrEqualTo(0.0);
        assertThat(result.avgUsPerSign()).isGreaterThanOrEqualTo(0.0);
        assertThat(result.totalVerifyMs()).isGreaterThanOrEqualTo(0.0);
        assertThat(result.avgUsPerVerify()).isGreaterThanOrEqualTo(0.0);
        assertThat(result.publicKeyBits()).isEqualTo(512);
        assertThat(result.privateKeyBits()).isGreaterThan(0);
        assertThat(result.signatureBytes()).isEqualTo("signature".getBytes(StandardCharsets.UTF_8).length);
        assertThat(result.verified()).isTrue();
        assertThat(result.sampleToken()).isEqualTo("header.payload.c2lnbmF0dXJl");
    }

    @Test
    @DisplayName("Reject benchmark runs with no iterations")
    void rejectsZeroIterations() {
        assertThatThrownBy(() -> benchmarkService.runSignatureBenchmark("TEST", 0, "payload"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Iterations must be at least 1");
    }

    private static class BenchmarkJwtSigning implements JwtSigning {

        private static final String SIGNATURE = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString("signature".getBytes(StandardCharsets.UTF_8));

        @Override
        public String algorithmId() {
            return "TEST";
        }

        @Override
        public String signJwt(final String payload) {
            return "header.payload.%s".formatted(SIGNATURE);
        }

        @Override
        public boolean verifyJwt(final String jwt) {
            return jwt.equals(signJwt("payload"));
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

    private static class RsaOnlyKeyManager implements KeyManager {

        private final KeyPair keyPair = createKeyPair();

        @Override
        public KeyPair getOrCreateKeyPair(final String algorithmCode) {
            return keyPair;
        }

        @Override
        public KeyPair generateKeyPair(final String algorithmCode) {
            return createKeyPair();
        }

        private static KeyPair createKeyPair() {
            try {
                final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
                generator.initialize(512);
                return generator.generateKeyPair();
            } catch (Exception e) {
                throw new IllegalStateException("Could not create test key pair", e);
            }
        }
    }
}
