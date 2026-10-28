package com.innowise.auth_service.security;

import com.innowise.auth_service.entity.Role;
import com.innowise.auth_service.entity.UserCredentials;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Encoders;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtServiceTest {

    private static final String SECRET = randomSecret();
    private static final String OTHER_SECRET = randomSecret();

    private final JwtService jwtService =
            new JwtService(new JwtProperties(SECRET, Duration.ofMinutes(15), Duration.ofDays(7)));

    private UserCredentials user;

    @BeforeEach
    void setUp() {
        user = new UserCredentials();
        user.setId(1L);
        user.setEmail("ivan@example.com");
        user.setRole(Role.USER);
    }

    @Test
    void generateAccessToken_shouldContainUserIdRoleAndAccessType() {
        Claims claims = jwtService.parseClaims(jwtService.generateAccessToken(user));

        assertThat(claims.getSubject()).isEqualTo("1");
        assertThat(claims.get(JwtService.ROLE_CLAIM, String.class)).isEqualTo("USER");
        assertThat(claims.get(JwtService.TYPE_CLAIM, String.class)).isEqualTo(JwtService.ACCESS_TOKEN_TYPE);
        assertThat(claims.getExpiration()).isAfter(new Date());
    }

    @Test
    void generateRefreshToken_shouldContainRefreshTypeWithoutRole() {
        Claims claims = jwtService.parseClaims(jwtService.generateRefreshToken(user));

        assertThat(claims.getSubject()).isEqualTo("1");
        assertThat(claims.get(JwtService.TYPE_CLAIM, String.class)).isEqualTo(JwtService.REFRESH_TOKEN_TYPE);
        assertThat(claims.get(JwtService.ROLE_CLAIM, String.class)).isNull();
    }

    @Test
    void parseClaims_shouldThrow_whenTokenIsSignedWithOtherKey() {
        JwtService otherService =
                new JwtService(new JwtProperties(OTHER_SECRET, Duration.ofMinutes(15), Duration.ofDays(7)));
        String token = otherService.generateAccessToken(user);

        assertThatThrownBy(() -> jwtService.parseClaims(token))
                .isInstanceOf(JwtException.class);
    }

    @Test
    void parseClaims_shouldThrow_whenTokenIsExpired() {
        JwtService expiredService =
                new JwtService(new JwtProperties(SECRET, Duration.ofSeconds(-1), Duration.ofDays(7)));
        String token = expiredService.generateAccessToken(user);

        assertThatThrownBy(() -> jwtService.parseClaims(token))
                .isInstanceOf(ExpiredJwtException.class);
    }

    private static String randomSecret() {
        return Encoders.BASE64.encode(Jwts.SIG.HS256.key().build().getEncoded());
    }
}
