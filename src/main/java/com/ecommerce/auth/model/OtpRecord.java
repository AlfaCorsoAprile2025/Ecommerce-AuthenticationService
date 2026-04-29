package com.ecommerce.auth.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Document("otp_records")
public class OtpRecord {

    @Id
    private String id;

    private String credentialId;

    /** Indice unico: un solo OTP attivo per email. */
    @Indexed(unique = true)
    private String email;

    /** OTP hashato con SHA-256 — mai memorizzato in chiaro. */
    private String otpHash;

    private LocalDateTime expiresAt;
    private LocalDateTime createdAt;
}
