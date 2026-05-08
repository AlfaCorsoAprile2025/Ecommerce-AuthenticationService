package com.ecommerce.auth.config;

import com.rabbitmq.client.Connection;
import com.rabbitmq.client.ConnectionFactory;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import reactor.core.scheduler.Schedulers;
import reactor.rabbitmq.ExchangeSpecification;
import reactor.rabbitmq.RabbitFlux;
import reactor.rabbitmq.Sender;
import reactor.rabbitmq.SenderOptions;
import reactor.core.publisher.Mono;

@Slf4j
@Configuration
public class RabbitMQConfig {

    @Value("${spring.rabbitmq.host:rabbitmq_broker}")
    private String host;

    @Value("${spring.rabbitmq.port:5672}")
    private int port;

    @Value("${spring.rabbitmq.username:guest}")
    private String username;

    @Value("${spring.rabbitmq.password:guest}")
    private String password;

    @Value("${spring.rabbitmq.virtual-host:/}")
    private String virtualHost;

    @Value("${messaging.rabbitmq.exchange:ecommerce.events}")
    private String exchange;

    @Value("${messaging.rabbitmq.mail-exchange:ecommerce.mail}")
    private String mailExchange;

    @Bean
    public Mono<Connection> rabbitConnection() {
        ConnectionFactory cf = new ConnectionFactory();
        cf.setHost(host);
        cf.setPort(port);
        cf.setUsername(username);
        cf.setPassword(password);
        cf.setVirtualHost(virtualHost);

        return Mono.fromCallable(cf::newConnection)
                .subscribeOn(Schedulers.boundedElastic())
                .doOnError(e -> log.error("[RabbitMQ] Connessione fallita: {}", e.getMessage()))
                .cache();
    }

    @Bean
    public Sender rabbitSender(Mono<Connection> rabbitConnection) {
        return RabbitFlux.createSender(new SenderOptions().connectionMono(rabbitConnection));
    }

    /**
     * Dichiara l'exchange al boot. Idempotente: se esiste già con gli stessi parametri RabbitMQ non fa nulla.
     * Code e binding sono responsabilità dell'AuditService (consumer).
     */
    @Bean
    public ApplicationRunner rabbitExchangeSetup(Sender sender) {
        return args -> sender
                .declareExchange(ExchangeSpecification.exchange(exchange).type("topic").durable(true))
                .doOnSuccess(r -> log.info("[RabbitMQ] Exchange dichiarato: {}", exchange))
                .then(sender.declareExchange(ExchangeSpecification.exchange(mailExchange).type("topic").durable(true)))
                .doOnSuccess(r -> log.info("[RabbitMQ] Exchange dichiarato: {}", mailExchange))
                .doOnError(e -> log.error("[RabbitMQ] Errore dichiarazione exchange: {}", e.getMessage()))
                .block();
    }
}
