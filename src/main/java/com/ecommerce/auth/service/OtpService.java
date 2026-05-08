package com.ecommerce.auth.service;

import com.ecommerce.auth.exception.AuthException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;

@Slf4j
@Service
@RequiredArgsConstructor
public class OtpService {

    private final ReactiveStringRedisTemplate redisTemplate;

    @Value("${otp.expiration-ms:300000}")
    private long expirationMs;

    @Value("${otp.length:6}")
    private int otpLength;

    private final SecureRandom secureRandom = new SecureRandom();

    public Mono<String> generateAndSave(String credentialId, String email) {
        int bound = (int) Math.pow(10, otpLength);
        String otp = String.format("%0" + otpLength + "d", secureRandom.nextInt(bound));
        String otpHash = hashSha256(otp);
        String key = "otp:" + email;

        return redisTemplate.opsForValue()
                .set(key, otpHash, Duration.ofMillis(expirationMs))
                .doOnSuccess(r -> log.debug("[OTP] Salvato per email={}", email))
                .thenReturn(otp);
    }

    public Mono<Void> validate(String email, String submittedOtp) {
        String key = "otp:" + email;
        return redisTemplate.opsForValue().get(key)
                .switchIfEmpty(Mono.error(new AuthException.InvalidOtpException()))
                .flatMap(storedHash ->
                        Mono.fromCallable(() -> hashSha256(submittedOtp))
                                .subscribeOn(Schedulers.boundedElastic())
                                .flatMap(submittedHash -> {
                                    if (!submittedHash.equals(storedHash)) {
                                        return Mono.error(new AuthException.InvalidOtpException());
                                    }
                                    return redisTemplate.delete(key).then();
                                })
                )
                .then();
    }

    private String hashSha256(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 non disponibile", e);
        }
    }
}
