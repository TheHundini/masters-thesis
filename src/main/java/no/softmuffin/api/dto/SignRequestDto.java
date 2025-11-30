package no.softmuffin.api.dto;

import jakarta.validation.constraints.NotBlank;

public record SignRequestDto(
        @NotBlank String algorithm,
        String payload
) {}
