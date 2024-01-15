package com.ahmedmq.boot.reactive.jwt.security.rememberme.security.jwt;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "jwt")
public record JwtProperties(String secretKey, long validityInMs) {

}