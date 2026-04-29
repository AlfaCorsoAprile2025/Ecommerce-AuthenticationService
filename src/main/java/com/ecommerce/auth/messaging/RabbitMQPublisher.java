package com.ecommerce.auth.messaging;

import com.ecommerce.auth.config.MessagingProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import reactor.rabbitmq.OutboundMessage;
import reactor.rabbitmq.Sender;

@Slf4j
@Component
@RequiredArgsConstructor
public class RabbitMQPublisher {

    private final Sender sender;
    private final ObjectMapper objectMapper;
    private final MessagingProperties messagingProperties;

    /**
     * Pubblica UserRegisteredEvent su RabbitMQ in modalità fire-and-forget.
     * Eventuali errori di connessione vengono loggati senza fallire il flusso di registrazione.
     */
    public Mono<Void> publishUserRegistered(UserRegisteredEvent event) {
        return Mono.fromCallable(() -> objectMapper.writeValueAsBytes(event))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(body -> {
                    String routingKey = messagingProperties.getRoutingKeys()
                            .getOrDefault("user-registered", "user.registered");
                    OutboundMessage message = new OutboundMessage(
                            messagingProperties.getExchange(),
                            routingKey,
                            body
                    );
                    return sender.send(Mono.just(message));
                })
                .doOnSuccess(v -> log.info("[RabbitMQ] Evento pubblicato: userId={}", event.getUserId()))
                .onErrorResume(e -> {
                    log.error("[RabbitMQ] Pubblicazione fallita per userId={}: {}", event.getUserId(), e.getMessage());
                    return Mono.empty();
                });
    }
}
