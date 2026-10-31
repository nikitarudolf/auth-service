package com.innowise.auth_service.service;

import com.innowise.auth_service.dto.LoginRequest;
import com.innowise.auth_service.dto.RegisterRequest;
import com.innowise.auth_service.dto.TokenRequest;
import com.innowise.auth_service.dto.TokenResponse;
import com.innowise.auth_service.dto.UserCredentialsResponse;
import com.innowise.auth_service.dto.ValidateResponse;
import com.innowise.auth_service.entity.Role;
import com.innowise.auth_service.entity.UserCredentials;
import com.innowise.auth_service.exception.InvalidCredentialsException;
import com.innowise.auth_service.exception.InvalidTokenException;
import com.innowise.auth_service.exception.ResourceAlreadyExistsException;
import com.innowise.auth_service.mapper.UserCredentialsMapper;
import com.innowise.auth_service.repository.UserCredentialsRepository;
import com.innowise.auth_service.security.JwtService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class AuthService {

    private static final String INVALID_CREDENTIALS_MESSAGE = "Invalid email or password";
    private static final String INVALID_TOKEN_MESSAGE = "Invalid or expired token";
    private static final String BEARER_PREFIX = "Bearer ";

    private final UserCredentialsRepository userCredentialsRepository;
    private final UserCredentialsMapper userCredentialsMapper;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    @Transactional
    public UserCredentialsResponse register(RegisterRequest request) {
        if (userCredentialsRepository.existsByEmail(request.email())) {
            throw new ResourceAlreadyExistsException("User with email " + request.email() + " already exists");
        }
        UserCredentials user = userCredentialsMapper.toEntity(request);
        user.setPasswordHash(passwordEncoder.encode(request.password()));
        user.setRole(Role.USER);
        return userCredentialsMapper.toResponse(userCredentialsRepository.save(user));
    }

    public TokenResponse login(LoginRequest request) {
        UserCredentials user = userCredentialsRepository.findByEmail(request.email())
                .orElseThrow(() -> new InvalidCredentialsException(INVALID_CREDENTIALS_MESSAGE));
        if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            throw new InvalidCredentialsException(INVALID_CREDENTIALS_MESSAGE);
        }
        return createTokens(user);
    }

    public TokenResponse refresh(TokenRequest request) {
        Claims claims = parseToken(request.token(), JwtService.REFRESH_TOKEN_TYPE);
        UserCredentials user = userCredentialsRepository.findById(Long.valueOf(claims.getSubject()))
                .orElseThrow(() -> new InvalidTokenException(INVALID_TOKEN_MESSAGE));
        return createTokens(user);
    }

    public ValidateResponse validate(TokenRequest request) {
        Claims claims = parseToken(request.token(), JwtService.ACCESS_TOKEN_TYPE);
        return new ValidateResponse(
                Long.valueOf(claims.getSubject()),
                Role.valueOf(claims.get(JwtService.ROLE_CLAIM, String.class)));
    }

    @Transactional
    public void delete(String authorizationHeader) {
        if (!authorizationHeader.startsWith(BEARER_PREFIX)) {
            throw new InvalidTokenException(INVALID_TOKEN_MESSAGE);
        }
        String token = authorizationHeader.substring(BEARER_PREFIX.length());
        Claims claims = parseToken(token, JwtService.ACCESS_TOKEN_TYPE);
        userCredentialsRepository.deleteById(Long.valueOf(claims.getSubject()));
    }

    private Claims parseToken(String token, String expectedType) {
        Claims claims;
        try {
            claims = jwtService.parseClaims(token);
        } catch (JwtException ex) {
            throw new InvalidTokenException(INVALID_TOKEN_MESSAGE);
        }
        if (!expectedType.equals(claims.get(JwtService.TYPE_CLAIM, String.class))) {
            throw new InvalidTokenException(INVALID_TOKEN_MESSAGE);
        }
        return claims;
    }

    private TokenResponse createTokens(UserCredentials user) {
        return new TokenResponse(jwtService.generateAccessToken(user), jwtService.generateRefreshToken(user));
    }
}
