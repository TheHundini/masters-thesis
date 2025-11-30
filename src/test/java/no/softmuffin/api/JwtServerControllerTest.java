package no.softmuffin.api;

import no.softmuffin.api.dto.BenchmarkResultDto;
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

    @Test
    @DisplayName("Benchmark RSA signing successfully")
    void benchmarkRsa() {
        BenchmarkResultDto result =
                signatureBenchmarkService.runSignatureBenchmark("RSA", 10, "test-payload-rsa");

        assertThat(result.algorithm()).isEqualTo("RSA");
        assertThat(result.iterations()).isEqualTo(10);
        assertThat(result.totalMs()).isGreaterThan(0.0);
        assertThat(result.avgUsPerSign()).isGreaterThan(0.0);
        assertThat(result.publicKeyBits()).isGreaterThan(0);
        assertThat(result.privateKeyBits()).isGreaterThan(0);
        assertThat(result.signatureBytes()).isGreaterThan(0);
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
        assertThat(result.totalMs()).isGreaterThan(0.0);
        assertThat(result.avgUsPerSign()).isGreaterThan(0.0);
        assertThat(result.publicKeyBits()).isGreaterThan(0);
        assertThat(result.privateKeyBits()).isGreaterThan(0);
        assertThat(result.signatureBytes()).isGreaterThan(0);
        assertThat(result.sampleToken()).isNotBlank();
    }
}