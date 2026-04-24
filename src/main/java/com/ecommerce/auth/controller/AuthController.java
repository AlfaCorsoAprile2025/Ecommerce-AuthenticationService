package com.ecommerce.auth.controller;

import com.ecommerce.auth.dto.*;
import com.ecommerce.auth.service.AuthorizationService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
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
