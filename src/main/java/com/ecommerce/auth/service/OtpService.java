package com.ecommerce.auth.service;

import com.ecommerce.auth.exception.AuthException;
import com.ecommerce.auth.model.OtpRecord;
import com.ecommerce.auth.repository.OtpRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Base64;

@Slf4j
@Service
@RequiredArgsConstructor
public class OtpService {

    private final OtpRepository otpRepository;

    @Value("${otp.expiration-ms:300000}")
    private long expirationMs;

    @Value("${otp.length:6}")
    private int otpLength;

    private final SecureRandom secureRandom = new SecureRandom();

    /**
     * Genera un OTP a N cifre, lo hasha con SHA-256, lo salva e ritorna il codice in chiaro
     * (necessario per includerlo nell'evento destinato al mailing service).
     */
    public Mono<String> generateAndSave(String credentialId, String email) {
        int bound = (int) Math.pow(10, otpLength);
        String otp = String.format("%0" + otpLength + "d", secureRandom.nextInt(bound));
        String otpHash = hashSha256(otp);
        LocalDateTime now = LocalDateTime.now();

        OtpRecord record = OtpRecord.builder()
                .credentialId(credentialId)
                .email(email)
                .otpHash(otpHash)
                .createdAt(now)
                .expiresAt(now.plus(expirationMs, ChronoUnit.MILLIS))
                .build();

        // Rimuove l'OTP precedente (se esiste) prima di salvarne uno nuovo
        return otpRepository.deleteByEmail(email)
                .then(otpRepository.save(record))
                .doOnSuccess(r -> log.debug("[OTP] Salvato per email={}", email))
                .thenReturn(otp);
    }

    /**
     * Valida l'OTP sottomesso dall'utente.
     * Cancella il record in caso di successo (monouso) o scadenza.
     */
    public Mono<Void> validate(String email, String submittedOtp) {
        return otpRepository.findByEmail(email)
                .switchIfEmpty(Mono.error(new AuthException.InvalidOtpException()))
                .flatMap(record -> {
                    if (record.getExpiresAt().isBefore(LocalDateTime.now())) {
                        return otpRepository.deleteById(record.getId())
                                .then(Mono.error(new AuthException.OtpExpiredException()));
                    }
                    return Mono.fromCallable(() -> hashSha256(submittedOtp))
                            .subscribeOn(Schedulers.boundedElastic())
                            .flatMap(submittedHash -> {
                                if (!submittedHash.equals(record.getOtpHash())) {
                                    return Mono.error(new AuthException.InvalidOtpException());
                                }
                                return otpRepository.deleteById(record.getId());
                            });
                })
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
