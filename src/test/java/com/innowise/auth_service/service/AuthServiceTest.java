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
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    private static final String EMAIL = "ivan@example.com";
    private static final String PASSWORD = "password123";
    private static final String PASSWORD_HASH = "hashed-password";

    @Mock
    private UserCredentialsRepository userCredentialsRepository;

    @Mock
    private UserCredentialsMapper userCredentialsMapper;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtService jwtService;

    @InjectMocks
    private AuthService authService;

    private UserCredentials user;

    @BeforeEach
    void setUp() {
        user = new UserCredentials();
        user.setId(1L);
        user.setEmail(EMAIL);
        user.setPasswordHash(PASSWORD_HASH);
        user.setRole(Role.USER);
    }

    @Test
    void register_shouldSaveUserWithHashedPasswordAndUserRole() {
        RegisterRequest request = new RegisterRequest(EMAIL, PASSWORD);
        UserCredentials newUser = new UserCredentials();
        UserCredentialsResponse response = new UserCredentialsResponse(1L, EMAIL, Role.USER, null);
        when(userCredentialsRepository.existsByEmail(EMAIL)).thenReturn(false);
        when(userCredentialsMapper.toEntity(request)).thenReturn(newUser);
        when(passwordEncoder.encode(PASSWORD)).thenReturn(PASSWORD_HASH);
        when(userCredentialsRepository.save(newUser)).thenReturn(newUser);
        when(userCredentialsMapper.toResponse(newUser)).thenReturn(response);

        UserCredentialsResponse result = authService.register(request);

        assertThat(result).isEqualTo(response);
        assertThat(newUser.getPasswordHash()).isEqualTo(PASSWORD_HASH);
        assertThat(newUser.getRole()).isEqualTo(Role.USER);
    }

    @Test
    void register_shouldThrow_whenEmailAlreadyExists() {
        RegisterRequest request = new RegisterRequest(EMAIL, PASSWORD);
        when(userCredentialsRepository.existsByEmail(EMAIL)).thenReturn(true);

        assertThatThrownBy(() -> authService.register(request))
                .isInstanceOf(ResourceAlreadyExistsException.class);
        verify(userCredentialsRepository, never()).save(any());
    }

    @Test
    void login_shouldReturnTokens_whenCredentialsAreValid() {
        when(userCredentialsRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(PASSWORD, PASSWORD_HASH)).thenReturn(true);
        when(jwtService.generateAccessToken(user)).thenReturn("access-token");
        when(jwtService.generateRefreshToken(user)).thenReturn("refresh-token");

        TokenResponse result = authService.login(new LoginRequest(EMAIL, PASSWORD));

        assertThat(result).isEqualTo(new TokenResponse("access-token", "refresh-token"));
    }

    @Test
    void login_shouldThrow_whenEmailNotFound() {
        LoginRequest request = new LoginRequest(EMAIL, PASSWORD);
        when(userCredentialsRepository.findByEmail(EMAIL)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.login(request))
                .isInstanceOf(InvalidCredentialsException.class);
    }

    @Test
    void login_shouldThrow_whenPasswordIsWrong() {
        LoginRequest request = new LoginRequest(EMAIL, "wrong-password");
        when(userCredentialsRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("wrong-password", PASSWORD_HASH)).thenReturn(false);

        assertThatThrownBy(() -> authService.login(request))
                .isInstanceOf(InvalidCredentialsException.class);
        verify(jwtService, never()).generateAccessToken(any());
    }

    @Test
    void refresh_shouldReturnNewTokens_whenRefreshTokenIsValid() {
        Claims claims = Jwts.claims().subject("1").add(JwtService.TYPE_CLAIM, JwtService.REFRESH_TOKEN_TYPE).build();
        when(jwtService.parseClaims("refresh-token")).thenReturn(claims);
        when(userCredentialsRepository.findById(1L)).thenReturn(Optional.of(user));
        when(jwtService.generateAccessToken(user)).thenReturn("new-access-token");
        when(jwtService.generateRefreshToken(user)).thenReturn("new-refresh-token");

        TokenResponse result = authService.refresh(new TokenRequest("refresh-token"));

        assertThat(result).isEqualTo(new TokenResponse("new-access-token", "new-refresh-token"));
    }

    @Test
    void refresh_shouldThrow_whenTokenIsInvalid() {
        TokenRequest request = new TokenRequest("bad-token");
        when(jwtService.parseClaims("bad-token")).thenThrow(new JwtException("Invalid token"));

        assertThatThrownBy(() -> authService.refresh(request))
                .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void refresh_shouldThrow_whenAccessTokenIsUsed() {
        Claims claims = Jwts.claims().subject("1").add(JwtService.TYPE_CLAIM, JwtService.ACCESS_TOKEN_TYPE).build();
        TokenRequest request = new TokenRequest("access-token");
        when(jwtService.parseClaims("access-token")).thenReturn(claims);

        assertThatThrownBy(() -> authService.refresh(request))
                .isInstanceOf(InvalidTokenException.class);
        verify(userCredentialsRepository, never()).findById(any());
    }

    @Test
    void refresh_shouldThrow_whenUserNotFound() {
        Claims claims = Jwts.claims().subject("1").add(JwtService.TYPE_CLAIM, JwtService.REFRESH_TOKEN_TYPE).build();
        when(jwtService.parseClaims("refresh-token")).thenReturn(claims);
        TokenRequest request = new TokenRequest("refresh-token");
        when(userCredentialsRepository.findById(1L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.refresh(request))
                .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void validate_shouldReturnUserIdAndRole_whenAccessTokenIsValid() {
        Claims claims = Jwts.claims()
                .subject("1")
                .add(JwtService.ROLE_CLAIM, "USER")
                .add(JwtService.TYPE_CLAIM, JwtService.ACCESS_TOKEN_TYPE)
                .build();
        when(jwtService.parseClaims("access-token")).thenReturn(claims);

        ValidateResponse result = authService.validate(new TokenRequest("access-token"));

        assertThat(result).isEqualTo(new ValidateResponse(1L, Role.USER));
    }

    @Test
    void validate_shouldThrow_whenRefreshTokenIsUsed() {
        Claims claims = Jwts.claims().subject("1").add(JwtService.TYPE_CLAIM, JwtService.REFRESH_TOKEN_TYPE).build();
        TokenRequest request = new TokenRequest("refresh-token");
        when(jwtService.parseClaims("refresh-token")).thenReturn(claims);

        assertThatThrownBy(() -> authService.validate(request))
                .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void delete_shouldDeleteUser_whenAccessTokenIsValid() {
        Claims claims = Jwts.claims().subject("1").add(JwtService.TYPE_CLAIM, JwtService.ACCESS_TOKEN_TYPE).build();
        when(jwtService.parseClaims("access-token")).thenReturn(claims);

        authService.delete("Bearer access-token");

        verify(userCredentialsRepository).deleteById(1L);
    }

    @Test
    void delete_shouldThrow_whenHeaderHasNoBearerPrefix() {
        assertThatThrownBy(() -> authService.delete("access-token"))
                .isInstanceOf(InvalidTokenException.class);
        verify(userCredentialsRepository, never()).deleteById(any());
    }

    @Test
    void delete_shouldThrow_whenRefreshTokenIsUsed() {
        Claims claims = Jwts.claims().subject("1").add(JwtService.TYPE_CLAIM, JwtService.REFRESH_TOKEN_TYPE).build();
        when(jwtService.parseClaims("refresh-token")).thenReturn(claims);

        assertThatThrownBy(() -> authService.delete("Bearer refresh-token"))
                .isInstanceOf(InvalidTokenException.class);
        verify(userCredentialsRepository, never()).deleteById(any());
    }
}
