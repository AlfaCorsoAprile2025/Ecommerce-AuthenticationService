package com.ecommerce.auth.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {
    private String secret;
    private long expirationMs;
    private String tempSecret;
    private long tempExpirationMs;
}
