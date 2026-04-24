package com.ecommerce.auth.service;

import com.ecommerce.auth.dto.*;
import com.ecommerce.auth.exception.AuthException;
import com.ecommerce.auth.model.Credentials;
import com.ecommerce.auth.model.Login_audit;
import com.ecommerce.auth.repository.CredentialsRepository;
import com.ecommerce.auth.repository.Login_auditRepository;
import com.ecommerce.auth.security.TokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthorizationService {

    private final CredentialsRepository credentialsRepository;
    private final Login_auditRepository login_auditRepository;
    private final TokenProvider tokenProvider;
    private final PasswordEncoder passwordEncoder;



    // LOGIN

    public Mono<AuthResponse> login(LoginRequest request) {
        return credentialsRepository.findByEmail(request.getEmail())
                .switchIfEmpty(Mono.error(new AuthException.InvalidCredentialsException()))
                .flatMap(credentials -> Mono.fromCallable(() -> {
                    String rawPassword = request.getPassword();
                    String dbPasswordHash = credentials.getPasswordHash();
                    // Esegui il match
                    return passwordEncoder.matches(rawPassword, dbPasswordHash);
                       }
                ).flatMap(matches -> {
                    Login_audit audit = Login_audit.builder()
                            .email(request.getEmail())
                            .successful(matches)
                            .timeStamp(java.time.LocalDateTime.now())
                            .build();
                    if (!matches) {
                        log.warn("Invalid password");
                        return login_auditRepository.save(audit).onErrorResume(e -> {
                                    log.error("Audit failure log failed: {}", e.getMessage());
                                    return Mono.empty();
                                })
                                .then(Mono.error(new AuthException.InvalidCredentialsException()));

                    }
                    return login_auditRepository.save(audit).onErrorResume(e -> {
                        log.error("Audit success log failed: {}", e.getMessage());
                        return Mono.empty();
                    }).then(buildLoginResponse(credentials));
                }));
    }

    private Mono<AuthResponse> buildLoginResponse(Credentials credentials) {
        List<String> roles = new ArrayList<>(List.of("ADMIN"));
        //List<String> roles = credentials.getRoles() != null ? credentials.getRoles() : List.of();
        String userId = credentials.getId();
        return tokenProvider.generateAccessToken(userId, roles)
                .map(token -> AuthResponse.builder()
                        .accessToken(token)
                        .tokenType("Bearer")
                        .expiresIn(tokenProvider.getExpirationMs() / 1000)
                        .userId(userId)
                        .roles(roles)
                        .build());

    }


}
