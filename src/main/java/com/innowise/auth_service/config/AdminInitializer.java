package com.innowise.auth_service.config;

import com.innowise.auth_service.entity.Role;
import com.innowise.auth_service.entity.UserCredentials;
import com.innowise.auth_service.repository.UserCredentialsRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Component
@RequiredArgsConstructor
public class AdminInitializer implements ApplicationRunner {

    private final UserCredentialsRepository userCredentialsRepository;
    private final PasswordEncoder passwordEncoder;
    private final AdminProperties adminProperties;

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        if (userCredentialsRepository.existsByEmail(adminProperties.email())) {
            return;
        }
        UserCredentials user = new UserCredentials();
        user.setEmail(adminProperties.email());
        user.setPasswordHash(passwordEncoder.encode(adminProperties.password()));
        user.setRole(Role.ADMIN);
        userCredentialsRepository.save(user);
        log.info("Admin user created: {}", adminProperties.email());
    }
}
