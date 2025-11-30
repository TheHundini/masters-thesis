package no.softmuffin.api.dto;

public record BenchmarkResultDto (
    String algorithm,
    int iterations,
    double totalMs,
    double avgUsPerSign,
    int publicKeyBits,
    int privateKeyBits,
    int signatureBytes,
    String sampleToken
) {}
