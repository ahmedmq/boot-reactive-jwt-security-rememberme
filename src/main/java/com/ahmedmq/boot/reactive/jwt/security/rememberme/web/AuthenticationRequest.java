package com.ahmedmq.boot.reactive.jwt.security.rememberme.web;

public record AuthenticationRequest(String personalAccessToken, Boolean rememberMe) {
}
