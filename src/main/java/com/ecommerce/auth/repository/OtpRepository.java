package com.ecommerce.auth.repository;

import com.ecommerce.auth.model.OtpRecord;
import org.springframework.data.mongodb.repository.ReactiveMongoRepository;
import reactor.core.publisher.Mono;

public interface OtpRepository extends ReactiveMongoRepository<OtpRecord, String> {
    Mono<OtpRecord> findByEmail(String email);
    Mono<Void> deleteByEmail(String email);
}
