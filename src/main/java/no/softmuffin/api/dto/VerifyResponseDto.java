package no.softmuffin.api.dto;

public record VerifyResponseDto(
        String algorithm,
        boolean valid
) {}
