package com.ecommerce.auth.dto;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.Builder;
import lombok.Data;

import java.util.List;


@Data
@Builder
@JsonNaming(PropertyNamingStrategies.LowerCamelCaseStrategy.class)
public class AuthResponse {
    private String accessToken;
    private String tokenType;
    private long expiresIn;
    private String userId;
    private List<String> roles;
}
