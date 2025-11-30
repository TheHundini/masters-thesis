package no.softmuffin.service;

import no.softmuffin.api.dto.BenchmarkResultDto;
import no.softmuffin.config.JWTMetricsUtil;
import no.softmuffin.config.KeyMetricsUtil;
import no.softmuffin.crypto.keys.KeyManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.security.KeyPair;


@Service
public class SignatureBenchmarkService {

    private static final Logger LOGGER = LoggerFactory.getLogger(SignatureBenchmarkService.class);

    private final SignatureService signatureService;
    private final KeyManager keyManager;

    public SignatureBenchmarkService(SignatureService signatureService, KeyManager keyManager) {
        this.signatureService = signatureService;
        this.keyManager = keyManager;
    }

    public BenchmarkResultDto runSignatureBenchmark(String algorithm, int iterations, String payload) {
        String lastToken = null;

        long start = System.nanoTime();
        for (int i = 0; i < iterations; i++) {
            lastToken = signatureService.generateSignedJwt(algorithm, "benchmark-payload");
        }
        long end = System.nanoTime();

        long totalNs = end - start;
        double totalMs = totalNs / 1_000_000.0;
        double avgUs = (totalNs / (double) iterations) / 1_000.0;

        // KeyPair metrics
        KeyPair keyPair = keyManager.getOrCreateKeyPair(algorithm);
        int publicKeyBits = KeyMetricsUtil.publicKeyBits(keyPair);
        int privateKeyBits = KeyMetricsUtil.privateKeyubits(keyPair);

        int signatureBytes = JWTMetricsUtil.getSignatureByteLength(lastToken);

        LOGGER.info(
                "Benchmark {}: iter={} totalMs={} avgUs={} pubBits={} privBits={} sigBytes={}",
                algorithm, iterations, totalMs, avgUs, publicKeyBits, privateKeyBits, signatureBytes
        );

        return new BenchmarkResultDto(
                algorithm,
                iterations,
                totalMs,
                avgUs,
                publicKeyBits,
                privateKeyBits,
                signatureBytes,
                lastToken
        );
    }
}
