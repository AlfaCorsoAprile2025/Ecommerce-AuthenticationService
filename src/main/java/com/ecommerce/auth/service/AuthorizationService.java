package com.ecommerce.auth.service;

import com.ecommerce.auth.dto.*;
import com.ecommerce.auth.exception.AuthException;
import com.ecommerce.auth.messaging.RabbitMQPublisher;
import com.ecommerce.auth.messaging.UserRegisteredEvent;
import com.ecommerce.auth.model.AccountStatus;
import com.ecommerce.auth.model.Credentials;
import com.ecommerce.auth.model.Login_audit;
import com.ecommerce.auth.model.UserRole;
import com.ecommerce.auth.repository.CredentialsRepository;
import com.ecommerce.auth.repository.Login_auditRepository;
import com.ecommerce.auth.repository.UserRoleRepository;
import com.ecommerce.auth.security.TokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthorizationService {

    private final CredentialsRepository credentialsRepository;
    private final Login_auditRepository login_auditRepository;
    private final TokenProvider tokenProvider;
    private final PasswordEncoder passwordEncoder;
    private final UserRoleRepository userRoleRepository;
    private final OtpService otpService;
    private final RabbitMQPublisher rabbitMQPublisher;


    // ===== REGISTRATION =====

    public Mono<Void> register(RegisterRequest request) {
        return credentialsRepository.existsByEmail(request.getEmail())
                .flatMap(exists -> {
                    if (exists) {
                        return Mono.error(new AuthException.EmailAlreadyExistsException(
                                "Email già registrata: " + request.getEmail()));
                    }

                    return Mono.fromCallable(() -> passwordEncoder.encode(request.getPassword()))
                            .flatMap(hash -> {
                                Credentials cred = Credentials.builder()
                                        .email(request.getEmail())
                                        .passwordHash(hash)
                                        .status(AccountStatus.PENDING_VERIFICATION)
                                        .createdAt(LocalDateTime.now())
                                        .updatedAt(LocalDateTime.now())
                                        .build();
                                return credentialsRepository.save(cred);
                            })
                            .flatMap(saved -> {
                                UserRole role = UserRole.builder()
                                        .credentialId(saved.getId())
                                        .role("USER")
                                        .build();
                                return userRoleRepository.save(role).thenReturn(saved);
                            })
                            .flatMap(saved ->
                                    otpService.generateAndSave(saved.getId(), request.getEmail())
                                            .flatMap(otp -> {
                                                UserRegisteredEvent event = UserRegisteredEvent.builder()
                                                        .eventId(UUID.randomUUID().toString())
                                                        .occurredAt(Instant.now())
                                                        .userId(saved.getId())
                                                        .email(request.getEmail())
                                                        .firstName(request.getFirstName())
                                                        .lastName(request.getLastName())
                                                        .initialRole("USER")
                                                        .otpCode(otp)
                                                        .build();

                                                // Fire-and-forget: RabbitMQ non bloccante sulla registrazione
                                                return rabbitMQPublisher.publishUserRegistered(event)
                                                        .onErrorResume(e -> Mono.empty());
                                            })
                            )
                            .doOnSuccess(v -> log.info("[register] Utente in attesa di verifica: {}", request.getEmail()))
                            .then();
                });
    }


    // ===== OTP VERIFICATION =====

    public Mono<Void> verifyOtp(OtpVerificationRequest request) {
        return credentialsRepository.findByEmail(request.getEmail())
                .switchIfEmpty(Mono.error(new AuthException.NotFoundException(
                        "Nessun account trovato per: " + request.getEmail())))
                .flatMap(credentials -> {
                    if (credentials.getStatus() == AccountStatus.ACTIVE) {
                        log.warn("[verifyOtp] Account già attivo: {}", request.getEmail());
                        return Mono.empty();
                    }
                    if (credentials.getStatus() != AccountStatus.PENDING_VERIFICATION) {
                        return Mono.error(new AuthException.AccountDisabledException());
                    }

                    return otpService.validate(request.getEmail(), request.getOtp())
                            .then(Mono.defer(() -> {
                                credentials.setStatus(AccountStatus.ACTIVE);
                                credentials.setUpdatedAt(LocalDateTime.now());
                                return credentialsRepository.save(credentials);
                            }))
                            .doOnSuccess(v -> log.info("[verifyOtp] Account attivato: {}", request.getEmail()));
                })
                .then();
    }


    // ===== LOGIN =====

    public Mono<AuthResponse> login(LoginRequest request) {
        return credentialsRepository.findByEmail(request.getEmail())
                .switchIfEmpty(Mono.error(new AuthException.InvalidCredentialsException()))
                .flatMap(credentials -> {
                    if (credentials.getStatus() == AccountStatus.PENDING_VERIFICATION) {
                        return Mono.error(new AuthException.AccountNotActivatedException());
                    }
                    return Mono.fromCallable(() ->
                            passwordEncoder.matches(request.getPassword(), credentials.getPasswordHash())
                    ).flatMap(matches -> {
                        Login_audit audit = Login_audit.builder()
                                .email(request.getEmail())
                                .successful(matches)
                                .timeStamp(LocalDateTime.now())
                                .build();
                        if (!matches) {
                            log.warn("[login] Password errata per: {}", request.getEmail());
                            return login_auditRepository.save(audit)
                                    .onErrorResume(e -> Mono.empty())
                                    .then(Mono.error(new AuthException.InvalidCredentialsException()));
                        }
                        return login_auditRepository.save(audit)
                                .onErrorResume(e -> Mono.empty())
                                .then(buildLoginResponse(credentials));
                    });
                });
    }

    private Mono<AuthResponse> buildLoginResponse(Credentials credentials) {
        String userId = credentials.getId();
        return userRoleRepository.findByCredentialId(userId)
                .map(UserRole::getRole)
                .collectList()
                .flatMap(roles ->
                        tokenProvider.generateAccessToken(userId, roles)
                                .map(token -> AuthResponse.builder()
                                        .accessToken(token)
                                        .tokenType("Bearer")
                                        .expiresIn(tokenProvider.getExpirationMs() / 1000)
                                        .userId(userId)
                                        .roles(roles)
                                        .build())
                );
    }


    // ===== TOKEN VALIDATION (pattern API Gateway) =====

    public Mono<TokenValidationResponse> validateToken(TokenValidationRequest request) {
        String raw = request.getToken();
        String token = raw.startsWith("Bearer ") ? raw.substring(7).trim() : raw.trim();

        return tokenProvider.validateAccessToken(token)
                .map(claims -> TokenValidationResponse.builder()
                        .valid(true)
                        .userId(claims.getSubject())
                        .roles(tokenProvider.extractRoles(claims))
                        .build())
                .onErrorReturn(TokenValidationResponse.builder()
                        .valid(false)
                        .build());
    }
}
