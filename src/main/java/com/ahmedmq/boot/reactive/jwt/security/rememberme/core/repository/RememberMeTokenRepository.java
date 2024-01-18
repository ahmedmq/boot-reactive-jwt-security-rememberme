package com.ahmedmq.boot.reactive.jwt.security.rememberme.core.repository;

import org.springframework.data.r2dbc.repository.R2dbcRepository;
import reactor.core.publisher.Mono;

public interface RememberMeTokenRepository extends R2dbcRepository<RememberedLogin, Long> {
    Mono<RememberedLogin> findBySeries(String series);

    Mono<Void> deleteByApiToken(String apiToken);
}
