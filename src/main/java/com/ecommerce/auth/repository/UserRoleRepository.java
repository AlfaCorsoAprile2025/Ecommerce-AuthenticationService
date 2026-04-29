package com.ecommerce.auth.repository;

import com.ecommerce.auth.model.UserRole;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface UserRoleRepository extends R2dbcRepository<UserRole, Long> {

    /** Tutti i ruoli di un utente — usato nella costruzione del JWT. */
    Flux<UserRole> findByCredentialId(String credentialId);

    /** Elimina tutti i ruoli di un utente (es. revoca ruoli). */
    Mono<Void> deleteByCredentialId(String credentialId);
}
