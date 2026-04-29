package com.ecommerce.auth.controller;

import com.ecommerce.auth.dto.*;
import com.ecommerce.auth.exception.AuthException;
import com.ecommerce.auth.service.AuthorizationService;
import com.ecommerce.auth.service.PermissionService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

/**
 */
@Slf4j
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthorizationService authService;
    private final PermissionService permissionService;

    @PostMapping("/login")
    public Mono<ResponseEntity<Object>> login(@Valid @RequestBody LoginRequest request) {
        return authService.login(request)
                .map(body -> ResponseEntity.ok(body));
    }

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public Mono<ResponseEntity<Void>> register(@Valid @RequestBody RegisterRequest request) {
        return authService.register(request)
                .thenReturn(ResponseEntity.<Void>status(HttpStatus.CREATED).build());
    }

    @PostMapping("/verify-otp")
    public Mono<ResponseEntity<Void>> verifyOtp(@Valid @RequestBody OtpVerificationRequest request) {
        return authService.verifyOtp(request)
                .thenReturn(ResponseEntity.<Void>ok().build());
    }

    @PostMapping("/validate-token")
    public Mono<ResponseEntity<TokenValidationResponse>> validateToken(
            @Valid @RequestBody TokenValidationRequest request) {
        return authService.validateToken(request)
                .map(r -> r.isValid()
                        ? ResponseEntity.ok(r)
                        : ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(r));
    }

    @GetMapping("/validate")
    public Mono<ResponseEntity<Void>> validateRequest(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestHeader(value = "X-Original-URI", required = false) String uri,
            @RequestHeader(value = "X-Original-Method", required = false) String method) {

        log.info("Validating request: {} {} with token present: {}", method, uri, authHeader != null);

        // 1. Estrai il token (rimuovendo "Bearer ")
        String token = (authHeader != null && authHeader.startsWith("Bearer "))
                ? authHeader.substring(7) : null;

        if (token == null) {
            return Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED).build());
        }

        // 2. Controlla validità del token E i permessi RBAC su MongoDB
        return permissionService.checkPermission(token, uri, method)
                .map(authContext -> ResponseEntity.ok()
                        .header("X-User-ID", authContext.getUserId())
                        .header("X-User-Role", authContext.getRole())
                        .<Void>build())
                .onErrorResume(AuthException.InvalidTokenException.class,
                        e -> Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED).build()))
                .onErrorResume(e -> Mono.just(ResponseEntity.status(HttpStatus.FORBIDDEN).build()));
    }

    @PostMapping("/hash-password")
    public Mono<ResponseEntity<String>> hashPassword(@RequestBody String rawPassword) {

        return Mono.fromSupplier(() -> {
            String hash = new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder(12)
                    .encode(rawPassword);

            log.info("Generated password hash");

            return ResponseEntity.ok(hash);
        });
    }


}
