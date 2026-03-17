package no.softmuffin.api;

import no.softmuffin.api.dto.BenchmarkResultDto;
import no.softmuffin.service.SignatureService;
import no.softmuffin.service.SignatureBenchmarkService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

@SpringBootTest
class JwtServerControllerTest {

    @Autowired
    private SignatureBenchmarkService signatureBenchmarkService;

    @Autowired
    private SignatureService signatureService;

    @Test
    @DisplayName("Benchmark RSA signing successfully")
    void benchmarkRsa() {
        BenchmarkResultDto result =
                signatureBenchmarkService.runSignatureBenchmark("RSA", 10, "test-payload-rsa");

        assertThat(result.algorithm()).isEqualTo("RSA");
        assertThat(result.iterations()).isEqualTo(10);
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

    @Test
    @DisplayName("Benchmark ML-DSA signing successfully")
    void benchmarkMldsa() {
        BenchmarkResultDto result = signatureBenchmarkService.runSignatureBenchmark(
                "ML-DSA",
                10,
                "test-payload-ml-dsa"
        );

        assertThat(result.algorithm()).isEqualTo("ML-DSA");
        assertThat(result.iterations()).isEqualTo(10);
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

    @Test
    @DisplayName("Benchmark SLH-DSA signing and verification successfully")
    void benchmarkSlhdsa() {
        BenchmarkResultDto result = signatureBenchmarkService.runSignatureBenchmark(
                "SLH-DSA",
                10,
                "test-payload-slh-dsa"
        );

        assertThat(result.algorithm()).isEqualTo("SLH-DSA");
        assertThat(result.iterations()).isEqualTo(10);
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

    @Test
    @DisplayName("Verify signed tokens with matching algorithm")
    void verifyMatchingAlgorithms() {
        assertVerifiedRoundTrip("RSA", "rsa-roundtrip");
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
}
