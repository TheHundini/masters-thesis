package no.softmuffin.api;

import no.softmuffin.api.dto.BenchmarkResultDto;
import no.softmuffin.service.SignatureService;
import no.softmuffin.service.SignatureBenchmarkService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

@SpringBootTest
class JwtServerControllerTest {

    @Autowired
    private SignatureBenchmarkService signatureBenchmarkService;

    @Autowired
    private SignatureService signatureService;

    @ParameterizedTest(name = "{0} benchmark returns valid metrics")
    @ValueSource(strings = {"RSA", "EC", "ML-DSA", "SLH-DSA"})
    @DisplayName("Benchmark each signing algorithm successfully")
    void benchmarkAlgorithms(final String algorithm) {
        final BenchmarkResultDto result =
                signatureBenchmarkService.runSignatureBenchmark(algorithm, 1, "test-payload");

        assertBenchmarkResult(result, algorithm);
    }

    @Test
    @DisplayName("Verify signed tokens with matching algorithm")
    void verifyMatchingAlgorithms() {
        assertVerifiedRoundTrip("RSA", "rsa-roundtrip");
        assertVerifiedRoundTrip("EC", "ec-roundtrip");
        assertVerifiedRoundTrip("ML-DSA", "mldsa-roundtrip");
        assertVerifiedRoundTrip("SLH-DSA", "slhdsa-roundtrip");
    }

    @Test
    @DisplayName("Reject token verification with wrong algorithm")
    void rejectWrongAlgorithm() {
        final String token = signatureService.generateSignedJwt("ML-DSA", "wrong-algorithm");

        final boolean valid = signatureService.verifySignedJwt("SLH-DSA", token);

        assertThat(valid).isFalse();
    }

    private void assertVerifiedRoundTrip(final String algorithm, final String payload) {
        final String token = signatureService.generateSignedJwt(algorithm, payload);

        assertThat(token).isNotBlank();
        assertThat(signatureService.verifySignedJwt(algorithm, token)).isTrue();
    }

    private void assertBenchmarkResult(final BenchmarkResultDto result, final String algorithm) {
        assertThat(result.algorithm()).isEqualTo(algorithm);
        assertThat(result.iterations()).isEqualTo(1);
        assertThat(result.totalSignMs()).isGreaterThan(0.0);
        assertThat(result.avgUsPerSign()).isGreaterThan(0.0);
        assertThat(result.totalVerifyMs()).isGreaterThan(0.0);
        assertThat(result.avgUsPerVerify()).isGreaterThan(0.0);
        assertThat(result.publicKeyBits()).isGreaterThan(0);
        assertThat(result.privateKeyBits()).isGreaterThan(0);
        assertThat(result.signatureBytes()).isGreaterThan(0);
        assertThat(result.verified()).isTrue();
        assertThat(result.sampleToken()).isNotBlank();
    }
}
