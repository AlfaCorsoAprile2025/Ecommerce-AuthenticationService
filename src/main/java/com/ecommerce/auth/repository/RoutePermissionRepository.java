package com.ecommerce.auth.repository;

import com.ecommerce.auth.model.RoutePermission;
import org.springframework.data.mongodb.repository.ReactiveMongoRepository;
import reactor.core.publisher.Flux;

public interface RoutePermissionRepository extends ReactiveMongoRepository<RoutePermission, String> {

    Flux<RoutePermission> findByHttpMethod(String httpMethod);
}
