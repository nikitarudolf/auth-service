package com.innowise.auth_service.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.innowise.auth_service.TestJwtConfiguration;
import com.innowise.auth_service.TestcontainersConfiguration;
import com.innowise.auth_service.config.AdminProperties;
import com.innowise.auth_service.dto.LoginRequest;
import com.innowise.auth_service.dto.RegisterRequest;
import com.innowise.auth_service.dto.TokenRequest;
import com.innowise.auth_service.dto.TokenResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Import({TestcontainersConfiguration.class, TestJwtConfiguration.class})
class AuthControllerIntegrationTest {

    private static final String EMAIL = "ivan@example.com";
    private static final String PASSWORD = "password123";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private AdminProperties adminProperties;

    @BeforeEach
    void cleanUp() {
        jdbcTemplate.execute("DELETE FROM user_credentials WHERE role <> 'ADMIN'");
    }

    @Test
    void register_shouldReturn201AndStoreHashedPassword() throws Exception {
        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new RegisterRequest(EMAIL, PASSWORD))))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").isNumber())
                .andExpect(jsonPath("$.email").value(EMAIL))
                .andExpect(jsonPath("$.role").value("USER"))
                .andExpect(jsonPath("$.password").doesNotExist())
                .andExpect(jsonPath("$.passwordHash").doesNotExist());

        String passwordHash = jdbcTemplate.queryForObject(
                "SELECT password_hash FROM user_credentials WHERE email = ?", String.class, EMAIL);
        assertThat(passwordHash).isNotEqualTo(PASSWORD).startsWith("$2");
    }

    @Test
    void register_shouldReturn409_whenEmailAlreadyExists() throws Exception {
        register(EMAIL, PASSWORD);

        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new RegisterRequest(EMAIL, PASSWORD))))
                .andExpect(status().isConflict());
    }

    @Test
    void register_shouldReturn400_whenRequestIsInvalid() throws Exception {
        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new RegisterRequest("not-an-email", "123"))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.email").exists())
                .andExpect(jsonPath("$.errors.password").exists());
    }

    @Test
    void login_shouldReturnTokens_whenCredentialsAreValid() throws Exception {
        register(EMAIL, PASSWORD);

        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginRequest(EMAIL, PASSWORD))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty());
    }

    @Test
    void login_shouldReturn401_whenPasswordIsWrong() throws Exception {
        register(EMAIL, PASSWORD);

        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginRequest(EMAIL, "wrong-password"))))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.detail").value("Invalid email or password"));
    }

    @Test
    void validate_shouldReturnUserIdAndRole_whenAccessTokenIsValid() throws Exception {
        register(EMAIL, PASSWORD);
        TokenResponse tokens = login(EMAIL, PASSWORD);

        mockMvc.perform(post("/api/v1/auth/validate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new TokenRequest(tokens.accessToken()))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userId").isNumber())
                .andExpect(jsonPath("$.role").value("USER"));
    }

    @Test
    void validate_shouldReturnAdminRole_forInitialAdmin() throws Exception {
        TokenResponse tokens = login(adminProperties.email(), adminProperties.password());

        mockMvc.perform(post("/api/v1/auth/validate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new TokenRequest(tokens.accessToken()))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.role").value("ADMIN"));
    }

    @Test
    void validate_shouldReturn401_whenRefreshTokenIsUsed() throws Exception {
        register(EMAIL, PASSWORD);
        TokenResponse tokens = login(EMAIL, PASSWORD);

        mockMvc.perform(post("/api/v1/auth/validate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new TokenRequest(tokens.refreshToken()))))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.detail").value("Invalid or expired token"));
    }

    @Test
    void refresh_shouldReturnNewTokens_whenRefreshTokenIsValid() throws Exception {
        register(EMAIL, PASSWORD);
        TokenResponse tokens = login(EMAIL, PASSWORD);

        mockMvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new TokenRequest(tokens.refreshToken()))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty());
    }

    @Test
    void refresh_shouldReturn401_whenAccessTokenIsUsed() throws Exception {
        register(EMAIL, PASSWORD);
        TokenResponse tokens = login(EMAIL, PASSWORD);

        mockMvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new TokenRequest(tokens.accessToken()))))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void unknownEndpoint_shouldReturn401() throws Exception {
        mockMvc.perform(get("/api/v1/unknown"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.detail").value("Authentication required"));
    }

    private void register(String email, String password) throws Exception {
        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new RegisterRequest(email, password))))
                .andExpect(status().isCreated());
    }

    private TokenResponse login(String email, String password) throws Exception {
        String json = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginRequest(email, password))))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return objectMapper.readValue(json, TokenResponse.class);
    }
}
