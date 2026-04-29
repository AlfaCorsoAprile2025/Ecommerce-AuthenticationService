package com.ecommerce.auth.controller;

import com.ecommerce.auth.dto.*;
import com.ecommerce.auth.service.AuthorizationService;
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
