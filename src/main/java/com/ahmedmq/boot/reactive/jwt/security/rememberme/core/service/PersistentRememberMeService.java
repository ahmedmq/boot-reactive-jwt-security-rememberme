package com.ahmedmq.boot.reactive.jwt.security.rememberme.core.service;


import com.ahmedmq.boot.reactive.jwt.security.rememberme.client.TrackerClient;
import com.ahmedmq.boot.reactive.jwt.security.rememberme.core.repository.RememberMeTokenRepository;
import com.ahmedmq.boot.reactive.jwt.security.rememberme.core.repository.RememberedLogin;
import com.ahmedmq.boot.reactive.jwt.security.rememberme.core.CookieHelper;
import com.ahmedmq.boot.reactive.jwt.security.rememberme.security.jwt.JwtTokenProvider;
import org.slf4j.Logger;
import org.springframework.boot.web.server.Cookie;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.util.retry.RetrySpec;

import java.time.Duration;
import java.util.Arrays;
import java.util.Map;
import java.util.UUID;


import static com.ahmedmq.boot.reactive.jwt.security.rememberme.core.CookieHelper.JWT_COOKIE_DURATION;
import static com.ahmedmq.boot.reactive.jwt.security.rememberme.core.CookieHelper.JWT_COOKIE_NAME;
import static com.ahmedmq.boot.reactive.jwt.security.rememberme.core.CookieHelper.REMEMBER_ME_COOKIE_DURATION;
import static com.ahmedmq.boot.reactive.jwt.security.rememberme.core.CookieHelper.REMEMBER_ME_COOKIE_LEEWAY_DURATION;
import static com.ahmedmq.boot.reactive.jwt.security.rememberme.core.CookieHelper.REMEMBER_ME_COOKIE_NAME;
import static com.ahmedmq.boot.reactive.jwt.security.rememberme.core.CookieHelper.encodeCookie;
import static java.time.LocalDateTime.now;

@Service
public class PersistentRememberMeService implements RememberMeService {

    private static final Logger log = org.slf4j.LoggerFactory.getLogger(PersistentRememberMeService.class);

    private final RememberMeTokenRepository tokenRepository;
    private final TrackerClient trackerClient;
    private final RememberMeTokenGenerator rememberMeTokenGenerator;
    private final JwtTokenProvider jwtTokenProvider;

    public PersistentRememberMeService(RememberMeTokenRepository tokenRepository, TrackerClient trackerClient, RememberMeTokenGenerator rememberMeTokenGenerator, JwtTokenProvider jwtTokenProvider) {
        this.tokenRepository = tokenRepository;
        this.trackerClient = trackerClient;
        this.rememberMeTokenGenerator = rememberMeTokenGenerator;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    public Mono<Authentication> autoLogin(ServerWebExchange exchange) {
        return extractRememberMeCookie(exchange)
                .retryWhen(RetrySpec.backoff(3, Duration.ofSeconds(1))
                        .filter(ex -> ex instanceof OptimisticLockingFailureException))
                .switchIfEmpty(Mono.empty())
                .flatMap(rememberedLogin -> loginUserWithPersistentToken(exchange, rememberedLogin));
    }

    public Mono<String> rememberMe(String trackerToken) {
        String series = UUID.randomUUID().toString();
        String tokenValue = rememberMeTokenGenerator.generate();

        RememberedLogin rememberedLogin = new RememberedLogin(
                trackerToken,
                series,
                tokenValue,
                now()
        );

        return tokenRepository.save(rememberedLogin).map(saved ->
                encodeCookie(new String[]{saved.getSeries(), saved.getTokenLatest()}));
    }

    private Mono<Authentication> loginUserWithPersistentToken(ServerWebExchange exchange, RememberedLogin rememberedLogin) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("X-TrackerToken", rememberedLogin.getApiToken());
        return trackerClient.me(headers, Map.of("fields", "id,email,api_token"))
                .map(response -> {
                    UserDetails userDetails = User
                            .withUsername(response.email()).password(response.apiToken())
                            .authorities("ROLE_USER")
                            .accountExpired(false)
                            .credentialsExpired(false)
                            .disabled(false)
                            .accountLocked(false)
                            .build();


                    UsernamePasswordAuthenticationToken authenticated = UsernamePasswordAuthenticationToken.authenticated(userDetails, userDetails.getPassword(), userDetails.getAuthorities());
                    String accessToken = jwtTokenProvider.createToken(authenticated);
                    ResponseCookie responseCookie = CookieHelper.create(JWT_COOKIE_NAME, accessToken, JWT_COOKIE_DURATION);
                    exchange.getResponse().addCookie(responseCookie);
                    return authenticated;
                });
    }

    private Mono<RememberedLogin> extractRememberMeCookie(ServerWebExchange exchange) {
        HttpCookie persistentCookie = exchange.getRequest().getCookies().getFirst(REMEMBER_ME_COOKIE_NAME);
        if (persistentCookie == null) {
            return Mono.empty();
        }
        if (!StringUtils.hasText(persistentCookie.getValue())) {
            return cancelCookie(exchange)
                    .then(Mono.empty());
        }
        String[] decodeCookie = CookieHelper.decodeCookie(persistentCookie.getValue());
        if (decodeCookie.length != 2) {
            log.debug("Cookie did not contain 2 tokens, but contained {} '"
                    , Arrays.asList(decodeCookie));
            return cancelCookie(exchange)
                    .then(Mono.empty());
        }
        String presentedSeries = decodeCookie[0];
        String presentedToken = decodeCookie[1];

        return tokenRepository.findBySeries(presentedSeries)
                .flatMap(token -> {
                    if (token.getTokenPreviousAt() != null) {
                        if (presentedToken.equals(token.getTokenPrevious()) &&
                                now().isBefore(token.getTokenLatestAt().plus(REMEMBER_ME_COOKIE_LEEWAY_DURATION))) {
                            log.debug("Request within leeway period of current token");
                            return Mono.just(token);
                        }
                    }
                    if (!presentedToken.equals(token.getTokenLatest())) {
                        log.debug("Invalid remember-me token (Series/token) mismatch. Implies previous cookie theft attack.");
                        return tokenRepository.deleteByApiToken(token.getApiToken())
                                .then(cancelCookie(exchange))
                                .then(Mono.empty());
                    }
                    if (token.getTokenLatestAt().isBefore(now().minusDays(REMEMBER_ME_COOKIE_DURATION.toDays()))) {
                        log.debug("Remember-me login has expired");
                        return cancelCookie(exchange)
                                .then(Mono.empty());
                    }
                    token.setTokenPrevious(token.getTokenLatest());
                    token.setTokenPreviousAt(token.getTokenLatestAt());
                    token.setTokenLatestAt(now());
                    token.setTokenLatest(this.rememberMeTokenGenerator.generate());
                    return tokenRepository.save(token)
                            .then(setCookie(exchange, token.getSeries(), token.getTokenLatest()))
                            .then(Mono.just(token));
                })
                .switchIfEmpty(cancelCookie(exchange).then(Mono.empty()));
    }

    private Mono<Void> cancelCookie(ServerWebExchange exchange) {
        return Mono.fromRunnable(() -> {
            var cookie = ResponseCookie
                    .from(REMEMBER_ME_COOKIE_NAME, "")
                    .httpOnly(true)
                    .maxAge(0)
                    .path("/")
                    .secure(true)
                    .sameSite(Cookie.SameSite.STRICT.toString())
                    .build();

            exchange.getResponse().addCookie(cookie);
        });
    }

    private Mono<Void> setCookie(ServerWebExchange exchange, String series, String tokenValue) {
        return Mono.fromRunnable(() -> {
            String value = encodeCookie(new String[]{series, tokenValue});
            var cookie = CookieHelper.create(REMEMBER_ME_COOKIE_NAME, value, REMEMBER_ME_COOKIE_DURATION);
            exchange.getResponse().addCookie(cookie);
        });
    }
}
