package com.innowise.auth_service.dto;

import com.innowise.auth_service.entity.Role;

public record ValidateResponse(
        Long userId,
        Role role
) {
}
