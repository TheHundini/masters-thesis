package no.softmuffin.api.dto;

public record BenchmarkResultDto (
    String algorithm,
    int iterations,
    double totalSignMs,
    double avgUsPerSign,
    double totalVerifyMs,
    double avgUsPerVerify,
    int publicKeyBits,
    int privateKeyBits,
    int signatureBytes,
    boolean verified,
    String sampleToken
) {}
