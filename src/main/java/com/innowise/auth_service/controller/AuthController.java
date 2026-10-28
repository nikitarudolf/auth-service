package com.innowise.auth_service.controller;

import com.innowise.auth_service.dto.LoginRequest;
import com.innowise.auth_service.dto.RegisterRequest;
import com.innowise.auth_service.dto.TokenRequest;
import com.innowise.auth_service.dto.TokenResponse;
import com.innowise.auth_service.dto.UserCredentialsResponse;
import com.innowise.auth_service.dto.ValidateResponse;
import com.innowise.auth_service.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<UserCredentialsResponse> register(@Valid @RequestBody RegisterRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(@Valid @RequestBody TokenRequest request) {
        return ResponseEntity.ok(authService.refresh(request));
    }

    @PostMapping("/validate")
    public ResponseEntity<ValidateResponse> validate(@Valid @RequestBody TokenRequest request) {
        return ResponseEntity.ok(authService.validate(request));
    }
}
