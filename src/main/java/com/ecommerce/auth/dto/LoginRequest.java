package com.ecommerce.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/** DTO login — solo le credenziali necessarie per l'autenticazione. */
@Data
public class LoginRequest {

    @NotBlank @Email
    private String email;

    @NotBlank
    private String password;

    private boolean rememberMe = false;
}
