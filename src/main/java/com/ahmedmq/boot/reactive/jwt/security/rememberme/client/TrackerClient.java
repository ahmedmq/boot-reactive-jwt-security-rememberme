package com.ahmedmq.boot.reactive.jwt.security.rememberme.client;

import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.service.annotation.GetExchange;
import reactor.core.publisher.Mono;

import java.util.Map;

public interface TrackerClient {

    @GetExchange("/me")
    Mono<ApiTokenResponse> me(@RequestHeader HttpHeaders headers,
                                 @RequestParam Map<String, String> params);
}
