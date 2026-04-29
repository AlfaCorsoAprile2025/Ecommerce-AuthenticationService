package com.ecommerce.auth.dto;

import lombok.Builder;
import lombok.Data;

import java.util.List;

/**
 * Risposta di POST /auth/validate-token.
 * valid=true  → HTTP 200 con userId e roles (usati dall'API Gateway per il routing).
 * valid=false → HTTP 401 (il controller mappa il flag sullo status code).
 */
@Data
@Builder
public class TokenValidationResponse {
    private boolean valid;
    private String userId;
    private List<String> roles;
}
