package com.ahmedmq.boot.reactive.jwt.security.rememberme.core.service;

import org.springframework.security.core.Authentication;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

public interface RememberMeService {

    Mono<Authentication> autoLogin(ServerWebExchange exchange);

    Mono<String> rememberMe(String trackerToken);
}
