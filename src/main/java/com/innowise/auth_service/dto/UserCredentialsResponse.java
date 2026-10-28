package com.innowise.auth_service.dto;

import com.innowise.auth_service.entity.Role;

import java.time.LocalDateTime;

public record UserCredentialsResponse(
        Long id,
        String email,
        Role role,
        LocalDateTime createdAt
) {
}
