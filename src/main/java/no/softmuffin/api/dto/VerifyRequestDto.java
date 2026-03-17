package no.softmuffin.api.dto;

import jakarta.validation.constraints.NotBlank;

public record VerifyRequestDto(
        @NotBlank String algorithm,
        @NotBlank String token
) {}
