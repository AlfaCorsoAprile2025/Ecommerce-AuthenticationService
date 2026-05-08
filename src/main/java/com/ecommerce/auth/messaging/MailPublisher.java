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

@Slf4j
@Service
@RequiredArgsConstructor
public class MailPublisher {

    private final Sender sender;
    private final ObjectMapper objectMapper;

    @Value("${messaging.rabbitmq.mail-exchange:ecommerce.mail}")
    private String exchange;

    public Mono<Void> publishOtpEvent(RegisterEventMessage registerEventMessage) {
        return Mono.fromCallable(() -> {
                    return objectMapper.writeValueAsBytes(registerEventMessage);
                })
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(bytes -> {
                    String routingKey = "email.register";
                    AMQP.BasicProperties props = new AMQP.BasicProperties.Builder()
                            .contentType("application/json")
                            .deliveryMode(2)
                            .build();
                    return sender.send(Mono.just(new OutboundMessage(exchange, routingKey, props, bytes)));
                })
                .doOnSuccess(v -> log.info("[MAilPublisher] operazione.{} con userId={}", registerEventMessage.getEmail().toLowerCase(), registerEventMessage.getOtp()))
                .onErrorResume(e -> {
                    log.error("[MailPublisher] operazione.{} con userId={}: {}", registerEventMessage.getEmail().toLowerCase(),  registerEventMessage.getOtp(), e.getMessage());
                    return Mono.empty();
                });
    }
}
