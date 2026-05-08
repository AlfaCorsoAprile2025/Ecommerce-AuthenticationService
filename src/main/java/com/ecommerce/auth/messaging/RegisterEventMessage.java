package com.ecommerce.auth.messaging;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RegisterEventMessage {

    private String eventId;
    private String email;
    private String otp;
    private Instant occurredAt;
}
