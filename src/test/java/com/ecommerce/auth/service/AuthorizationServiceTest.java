package com.ecommerce.auth.service;

import com.ecommerce.auth.config.JwtProperties;
import com.ecommerce.auth.dto.LoginRequest;
import com.ecommerce.auth.exception.AuthException;
import com.ecommerce.auth.model.Credentials;
import com.ecommerce.auth.repository.CredentialsRepository;
import com.ecommerce.auth.repository.Login_auditRepository;
import com.ecommerce.auth.security.TokenProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthorizationServiceTest {

    @Mock private CredentialsRepository credentialsRepository;
    @Mock private Login_auditRepository login_auditRepository;

    private AuthorizationService authService;
    private TokenProvider tokenProvider;
    private PasswordEncoder passwordEncoder;

    private static final String USER_ID = UUID.randomUUID().toString();
    private static final String EMAIL = "mario.rossi@test.it";
    private static final String RAW_PASSWORD = "Password1!";

    @BeforeEach
    void setUp() {
        passwordEncoder = new BCryptPasswordEncoder(4);

        JwtProperties jwtProperties = new JwtProperties();
        jwtProperties.setSecret("testSecretKeyThatIsAtLeast256BitsLongForHMAC");
        jwtProperties.setExpirationMs(3_600_000L);
        jwtProperties.setTempSecret("tempSecretKeyThatIsAtLeast256BitsLong!!");
        jwtProperties.setTempExpirationMs(300_000L);

        tokenProvider = new TokenProvider(jwtProperties);

        authService = new AuthorizationService(
                credentialsRepository, login_auditRepository,
                tokenProvider, passwordEncoder
        );
    }


    // LOGIN

    @Test
    @DisplayName("login: credenziali corrette, no OTP → AuthResponse con JWT")
    void login_validCredentials_noOtp_returnsAuthResponse() {
        LoginRequest request = new LoginRequest();
        request.setEmail(EMAIL);
        request.setPassword(RAW_PASSWORD);

        Credentials credentials = Credentials.builder()
                .id(USER_ID).email(EMAIL)
                .passwordHash(passwordEncoder.encode(RAW_PASSWORD))
                .roles(List.of("ADMIN"))
                .build();

        when(credentialsRepository.findByEmail(EMAIL)).thenReturn(Mono.just(credentials));

        StepVerifier.create(authService.login(request))
                .assertNext(result -> {
                    var auth = (com.ecommerce.auth.dto.AuthResponse) result;
                    assertThat(auth.getAccessToken()).isNotBlank();
                    assertThat(auth.getRoles()).contains("ADMIN");
                    assertThat(auth.getUserId()).isEqualTo(USER_ID);
                })
                .verifyComplete();
    }

    @Test
    @DisplayName("login: password errata → InvalidCredentialsException")
    void login_wrongPassword_throwsUnauthorized() {
        LoginRequest request = new LoginRequest();
        request.setEmail(EMAIL);
        request.setPassword("WrongPassword1!");

        Credentials credentials = Credentials.builder()
                .id(USER_ID).email(EMAIL)
                .passwordHash(passwordEncoder.encode(RAW_PASSWORD))
                .roles(List.of("USER"))
                .build();

        when(credentialsRepository.findByEmail(EMAIL)).thenReturn(Mono.just(credentials));

        StepVerifier.create(authService.login(request))
                .expectError(AuthException.InvalidCredentialsException.class)
                .verify();
    }

    @Test
    @DisplayName("login: email inesistente → InvalidCredentialsException (no user enumeration)")
    void login_unknownEmail_sameErrorAsWrongPassword() {
        LoginRequest request = new LoginRequest();
        request.setEmail("unknown@test.it");
        request.setPassword(RAW_PASSWORD);

        when(credentialsRepository.findByEmail("unknown@test.it")).thenReturn(Mono.empty());

        StepVerifier.create(authService.login(request))
                .expectError(AuthException.InvalidCredentialsException.class)
                .verify();
    }


}
