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
public class LoginEventMessage {

    private String eventId;
    private String userId;
    private String email;
    /** REGISTERED | LOGIN_SUCCESS | LOGIN_FAILED | LOGOUT */
    private String eventType;
    private boolean successful;
    private Instant occurredAt;
}
