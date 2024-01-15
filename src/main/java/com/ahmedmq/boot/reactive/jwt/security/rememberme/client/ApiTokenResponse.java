package com.ahmedmq.boot.reactive.jwt.security.rememberme.client;

import com.fasterxml.jackson.annotation.JsonProperty;

public record ApiTokenResponse(String email, @JsonProperty("api_token") String apiToken, int id) {
}
