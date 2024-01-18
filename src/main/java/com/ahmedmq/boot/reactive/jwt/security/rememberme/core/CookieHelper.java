package com.ahmedmq.boot.reactive.jwt.security.rememberme.core;

import org.springframework.boot.web.server.Cookie;
import org.springframework.http.ResponseCookie;
import org.springframework.util.StringUtils;

import java.time.Duration;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.springframework.web.util.UriUtils.decode;
import static org.springframework.web.util.UriUtils.encode;

public class CookieHelper {

    private CookieHelper() {
    }


    public static final String JWT_COOKIE_NAME = "jwt_token";
    public static final Duration JWT_COOKIE_DURATION = Duration.ofMinutes(10);
    public static final String REMEMBER_ME_COOKIE_NAME = "remember_me";
    public static final Duration REMEMBER_ME_COOKIE_DURATION = Duration.ofDays(7);
    public static final Duration REMEMBER_ME_COOKIE_LEEWAY_DURATION = Duration.ofMinutes(1);

    private static final String DELIMITER = ":";

    public static ResponseCookie create(String name, String value, Duration duration) {
        return ResponseCookie.from(name, value)
                .httpOnly(true)
                .secure(true)
                .maxAge(duration)
                .sameSite(Cookie.SameSite.STRICT.toString())
                .path("/")
                .build();
    }

    public static ResponseCookie cancel(String name) {
        return ResponseCookie.from(name, "")
                .httpOnly(true)
                .secure(true)
                .maxAge(0)
                .sameSite(Cookie.SameSite.STRICT.toString())
                .path("/")
                .build();
    }

    public static String encodeCookie(String[] cookieTokens) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < cookieTokens.length; i++) {
            sb.append(encode(cookieTokens[i], UTF_8));
            if (i < cookieTokens.length - 1) {
                sb.append(DELIMITER);
            }
        }
        String value = sb.toString();
        sb = new StringBuilder(Base64.getEncoder().encodeToString(value.getBytes()));
        while (sb.charAt(sb.length() - 1) == '=') {
            sb.deleteCharAt(sb.length() - 1);
        }
        return sb.toString();
    }

    public static String[] decodeCookie(String cookieValue) {
        String modifiedCookieValue = cookieValue;
        for (int j = 0; j < modifiedCookieValue.length() % 4; j++) {
            modifiedCookieValue = modifiedCookieValue + "=";
        }
        String cookieAsPlainText = new String(Base64.getDecoder().decode(modifiedCookieValue));
        String[] tokens = StringUtils.delimitedListToStringArray(cookieAsPlainText, DELIMITER);
        for (int i = 0; i < tokens.length; i++) {
            tokens[i] = decode(tokens[i], UTF_8);
        }
        return tokens;
    }
}
