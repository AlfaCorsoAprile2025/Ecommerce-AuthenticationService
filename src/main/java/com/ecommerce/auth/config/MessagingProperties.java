package com.ecommerce.auth.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.HashMap;
import java.util.Map;

@Data
@ConfigurationProperties(prefix = "messaging.rabbitmq")
public class MessagingProperties {
    private String exchange = "ecommerce.events";
    private Map<String, String> routingKeys = new HashMap<>();
}
