package com.ahmedmq.boot.reactive.jwt.security.rememberme.core.filter;

import com.ahmedmq.boot.reactive.jwt.security.rememberme.core.service.RememberMeService;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

public class PersistentRememberMeAuthenticationFilter implements WebFilter {

    private final RememberMeService rememberMeService;

    public PersistentRememberMeAuthenticationFilter(RememberMeService rememberMeService) {
        this.rememberMeService = rememberMeService;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return ReactiveSecurityContextHolder.getContext()
                .switchIfEmpty(Mono.defer(() -> rememberMeService.autoLogin(exchange)
                        .switchIfEmpty(chain.filter(exchange).then(Mono.empty()))
                        .flatMap(rememberMeAuth -> chain.filter(exchange)
                                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(rememberMeAuth))
                                .then(Mono.empty()))))
                .flatMap(securityContext -> chain.filter(exchange));
    }
}
