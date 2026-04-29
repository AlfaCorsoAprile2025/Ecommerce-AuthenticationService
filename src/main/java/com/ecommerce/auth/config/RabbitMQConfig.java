package com.ecommerce.auth.config;

import com.rabbitmq.client.ConnectionFactory;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import reactor.core.scheduler.Schedulers;
import reactor.rabbitmq.RabbitFlux;
import reactor.rabbitmq.Sender;
import reactor.rabbitmq.SenderOptions;
import reactor.core.publisher.Mono;

@Slf4j
@Configuration
public class RabbitMQConfig {

    @Value("${spring.rabbitmq.host:localhost}")
    private String host;

    @Value("${spring.rabbitmq.port:5672}")
    private int port;

    @Value("${spring.rabbitmq.username:guest}")
    private String username;

    @Value("${spring.rabbitmq.password:guest}")
    private String password;

    @Value("${spring.rabbitmq.virtual-host:/}")
    private String virtualHost;

    @Bean
    public Sender rabbitSender() {
        ConnectionFactory cf = new ConnectionFactory();
        cf.setHost(host);
        cf.setPort(port);
        cf.setUsername(username);
        cf.setPassword(password);
        cf.setVirtualHost(virtualHost);

        SenderOptions options = new SenderOptions()
                .connectionMono(
                        Mono.fromCallable(cf::newConnection)
                                .subscribeOn(Schedulers.boundedElastic())
                                .doOnError(e -> log.error("[RabbitMQ] Connessione fallita: {}", e.getMessage()))
                                .cache()
                );

        return RabbitFlux.createSender(options);
    }
}
