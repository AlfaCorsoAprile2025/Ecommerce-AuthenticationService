package com.ecommerce.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

@Data
public class OtpVerificationRequest {

    @NotBlank(message = "Email obbligatoria")
    @Email(message = "Formato email non valido")
    private String email;

    @NotBlank(message = "OTP obbligatorio")
    @Pattern(regexp = "\\d{6}", message = "OTP deve essere di 6 cifre")
    private String otp;
}
