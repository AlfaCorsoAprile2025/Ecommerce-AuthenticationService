package com.ecommerce.auth.security;

import com.ecommerce.auth.config.JwtProperties;
import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import reactor.test.StepVerifier;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test del TokenProvider — verifica isolata del componente JWT.
 * Nessun mock necessario: TokenProvider è puro (no I/O).
 */
class TokenProviderTest {

    private TokenProvider tokenProvider;
    private static final String USER_ID = UUID.randomUUID().toString();

    @BeforeEach
    void setUp() {
        JwtProperties props = new JwtProperties();
        props.setSecret("testSecretKeyThatIsAtLeast256BitsLongForHMAC");
        props.setExpirationMs(3_600_000L);
        props.setTempSecret("tempSecretKeyThatIsAtLeast256BitsLong!!");
        props.setTempExpirationMs(300_000L);
        tokenProvider = new TokenProvider(props);
    }

    @Test
    @DisplayName("generateAccessToken → token valido con userId e ruoli")
    void generateAndValidateAccessToken() {
        List<String> roles = List.of("USER", "ADMIN");

        StepVerifier.create(
                tokenProvider.generateAccessToken(USER_ID, roles)
                        .flatMap(tokenProvider::validateAccessToken)
        )
        .assertNext(claims -> {
            assertThat(claims.getSubject()).isEqualTo(USER_ID);
            assertThat(tokenProvider.extractRoles(claims)).containsExactlyInAnyOrder("USER", "ADMIN");
        })
        .verifyComplete();
    }


    @Test
    @DisplayName("token manomesso → errore di validazione firma")
    void tamperedToken_failsValidation() {
        StepVerifier.create(
                tokenProvider.generateAccessToken(USER_ID, List.of("USER"))
                        .flatMap(token -> tokenProvider.validateAccessToken(token + "tampered"))
        )
        .expectError()
        .verify();
    }
}
