package com.ecommerce.auth.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/** DTO per POST /auth/validate-token — chiamato dall'API Gateway. */
@Data
public class TokenValidationRequest {

    @NotBlank
    private String token;
}
