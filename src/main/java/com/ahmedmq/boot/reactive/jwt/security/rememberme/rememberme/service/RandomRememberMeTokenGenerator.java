package com.ahmedmq.boot.reactive.jwt.security.rememberme.rememberme.service;

import org.springframework.stereotype.Component;

import java.util.Base64;
import java.util.Random;

import static org.springframework.security.web.authentication.rememberme.PersistentTokenBasedRememberMeServices.DEFAULT_TOKEN_LENGTH;

@Component
public class RandomRememberMeTokenGenerator implements RememberMeTokenGenerator {
    @Override
    public String generate() {
        byte[] newToken = new byte[DEFAULT_TOKEN_LENGTH];
        var random = new Random();
        random.nextBytes(newToken);
        return Base64.getEncoder().encodeToString(newToken);
    }
}
