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

        long signStart = System.nanoTime();
        for (int i = 0; i < iterations; i++) {
            lastToken = signatureService.generateSignedJwt(algorithm, payload);
        }
        long signEnd = System.nanoTime();

        long totalSignNs = signEnd - signStart;
        double totalSignMs = totalSignNs / 1_000_000.0;
        double avgUsPerSign = (totalSignNs / (double) iterations) / 1_000.0;

        boolean verified = false;
        long verifyStart = System.nanoTime();
        for (int i = 0; i < iterations; i++) {
            verified = signatureService.verifySignedJwt(algorithm, lastToken);
        }
        long verifyEnd = System.nanoTime();

        long totalVerifyNs = verifyEnd - verifyStart;
        double totalVerifyMs = totalVerifyNs / 1_000_000.0;
        double avgUsPerVerify = (totalVerifyNs / (double) iterations) / 1_000.0;

        // KeyPair metrics
        KeyPair keyPair = keyManager.getOrCreateKeyPair(algorithm);
        int publicKeyBits = KeyMetricsUtil.publicKeyBits(keyPair);
        int privateKeyBits = KeyMetricsUtil.privateKeyubits(keyPair);

        int signatureBytes = JWTMetricsUtil.getSignatureByteLength(lastToken);

        LOGGER.info(
                "Benchmark {}: iter={} signMs={} signUs={} verifyMs={} verifyUs={} pubBits={} privBits={} sigBytes={} verified={}",
                algorithm,
                iterations,
                totalSignMs,
                avgUsPerSign,
                totalVerifyMs,
                avgUsPerVerify,
                publicKeyBits,
                privateKeyBits,
                signatureBytes,
                verified
        );

        return new BenchmarkResultDto(
                algorithm,
                iterations,
                totalSignMs,
                avgUsPerSign,
                totalVerifyMs,
                avgUsPerVerify,
                publicKeyBits,
                privateKeyBits,
                signatureBytes,
                verified,
                lastToken
        );
    }
}
