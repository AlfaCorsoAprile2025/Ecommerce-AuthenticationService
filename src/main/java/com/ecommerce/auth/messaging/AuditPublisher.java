package com.ecommerce.auth.messaging;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.rabbitmq.client.AMQP;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import reactor.rabbitmq.OutboundMessage;
import reactor.rabbitmq.Sender;

import java.time.Instant;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuditPublisher {

    private final Sender sender;
    private final ObjectMapper objectMapper;

    @Value("${messaging.rabbitmq.exchange:ecommerce.events}")
    private String exchange;

    /**
     * Pubblica un evento prodotto sull'exchange topic.
     * Routing key: product.{operation lowercase} (es: product.created → audit.product via binding product.*)
     * L'errore non propaga al chiamante: l'audit è fire-and-forget rispetto al flusso principale.
     */
    public Mono<Void> publishLoginEvent(LoginEventMessage loginEventMessage) {
        return Mono.fromCallable(() -> {
                    return objectMapper.writeValueAsBytes(loginEventMessage);
                })
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(bytes -> {
                    String routingKey = "product." + loginEventMessage.getEventType();
                    AMQP.BasicProperties props = new AMQP.BasicProperties.Builder()
                            .contentType("application/json")
                            .deliveryMode(2)
                            .build();
                    return sender.send(Mono.just(new OutboundMessage(exchange, routingKey, props, bytes)));
                })
                .doOnSuccess(v -> log.info("[AuditPublisher] operazione.{} con userId={}", loginEventMessage.getEventType().toLowerCase(), loginEventMessage.getUserId()))
                .onErrorResume(e -> {
                    log.error("[AuditPublisher] operazione.{} con userId={}: {}", loginEventMessage.getEventType().toLowerCase(),  loginEventMessage.getUserId(), e.getMessage());
                    return Mono.empty();
                });
    }
}
