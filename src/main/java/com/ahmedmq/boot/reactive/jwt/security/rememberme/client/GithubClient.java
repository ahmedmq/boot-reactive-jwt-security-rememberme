package com.ahmedmq.boot.reactive.jwt.security.rememberme.client;

import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.service.annotation.GetExchange;
import reactor.core.publisher.Mono;

public interface GithubClient {

    @GetExchange("/user")
    Mono<UserResponse> user(@RequestHeader("headers") HttpHeaders headers);
}
