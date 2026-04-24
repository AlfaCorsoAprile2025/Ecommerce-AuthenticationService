package com.ecommerce.auth.repository;

import com.ecommerce.auth.model.Credentials;
import org.springframework.data.mongodb.repository.ReactiveMongoRepository;
import reactor.core.publisher.Mono;



// è un interfaccia ma viene istanziata da spring data con proxy pattern
public interface CredentialsRepository extends ReactiveMongoRepository<Credentials, String> {

    Mono<Credentials> findByEmail(String email);

    Mono<Boolean> existsByEmail(String email);
}
