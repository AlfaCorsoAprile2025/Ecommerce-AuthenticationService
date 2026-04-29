package com.ecommerce.auth.repository;

import com.ecommerce.auth.model.Login_audit;
import org.springframework.data.mongodb.repository.ReactiveMongoRepository;
import reactor.core.publisher.Mono;

// è un interfaccia ma viene istanziata da spring data con proxy pattern
public interface Login_auditRepository extends ReactiveMongoRepository<Login_audit, String> {

    Mono<Login_audit> findByEmail(String email);

    Mono<Boolean> existsByEmail(String email);

    // save(Login_audit) è ereditato da ReactiveMongoRepository con return type Mono<Login_audit>
}
