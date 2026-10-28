package com.innowise.auth_service;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Encoders;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.test.context.DynamicPropertyRegistrar;

@TestConfiguration(proxyBeanMethods = false)
public class TestJwtConfiguration {

    @Bean
    DynamicPropertyRegistrar jwtSecretRegistrar() {
        String secret = Encoders.BASE64.encode(Jwts.SIG.HS256.key().build().getEncoded());
        return registry -> registry.add("jwt.secret", () -> secret);
    }
}
