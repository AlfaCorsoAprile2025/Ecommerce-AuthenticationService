package com.ecommerce.auth.dto;

import lombok.Builder;
import lombok.Data;

import java.util.List;


@Data
@Builder
public class AuthResponse {
    private String accessToken;
    private String tokenType;
    private long expiresIn;
    private String userId;
    private List<String> roles;
}
