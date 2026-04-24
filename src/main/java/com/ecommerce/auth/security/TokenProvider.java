package com.ecommerce.auth.security;

import com.ecommerce.auth.config.JwtProperties;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;

@Slf4j
@Component
public class TokenProvider {

    private static final String CLAIM_ROLES = "roles";
    private static final String TYPE_ACCESS = "access";

    private final SecretKey accessKey;
    private final JwtProperties jwtProperties;

    public TokenProvider(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
        this.accessKey = Keys.hmacShaKeyFor(
                jwtProperties.getSecret().getBytes(StandardCharsets.UTF_8)
        );
    }

    // =========================================================================
    // GENERAZIONE TOKEN
    // =========================================================================

    /**
     * Genera il JWT definitivo per un utente autenticato.
     * Contiene userId, ruoli e un JTI univoco per la blacklist.
     */
    public Mono<String> generateAccessToken(String userId, List<String> roles) {
        return Mono.fromCallable(() ->{
            Instant now = Instant.now();
            return Jwts.builder()
                    .subject(userId)
                    .claim(CLAIM_ROLES, roles)
                    .id(UUID.randomUUID().toString())   // JTI per blacklist
                    .issuedAt(Date.from(now))
                    .expiration(Date.from(now.plusMillis(jwtProperties.getExpirationMs())))
                    .signWith(accessKey)
                    .compact();});
    }


    // =========================================================================
    // VALIDAZIONE E PARSING
    // =========================================================================

    /**
     * Valida e parsa un accessToken. Ritorna Mono.error se non valido.
     */
    public Mono<Claims> validateAccessToken(String token) {
        return parseToken(token, accessKey);
    }


    private Mono<Claims> parseToken(String token, SecretKey key) {
        return Mono.fromCallable(() ->
                Jwts.parser()
                        .verifyWith(key)
                        .build()
                        .parseSignedClaims(token)
                        .getPayload()
        ).onErrorMap(e -> {
            log.debug("[TokenProvider] Validazione token fallita: {}", e.getMessage());
            return new JwtException("Token non valido o scaduto", e);
        });
    }

    @SuppressWarnings("unchecked")
    public List<String> extractRoles(Claims claims) {
        return claims.get(CLAIM_ROLES, List.class);
    }

    public long getExpirationMs() {
        return jwtProperties.getExpirationMs();
    }
}
