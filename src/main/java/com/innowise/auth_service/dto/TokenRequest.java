package com.innowise.auth_service.dto;

import jakarta.validation.constraints.NotBlank;

public record TokenRequest(
        @NotBlank String token
) {
}
