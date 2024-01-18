package com.ahmedmq.boot.reactive.jwt.security.rememberme.web;

import com.ahmedmq.boot.reactive.jwt.security.rememberme.client.TrackerClient;
import com.ahmedmq.boot.reactive.jwt.security.rememberme.core.service.RememberMeService;
import com.ahmedmq.boot.reactive.jwt.security.rememberme.core.CookieHelper;
import com.ahmedmq.boot.reactive.jwt.security.rememberme.security.jwt.JwtTokenProvider;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.Map;

import static org.springframework.http.HttpHeaders.SET_COOKIE;

@RestController
@RequestMapping("/auth")
@Validated
public class AuthController {

    private final JwtTokenProvider tokenProvider;

    private final ReactiveAuthenticationManager authenticationManager;

    private final RememberMeService rememberMeService;

    private final TrackerClient trackerClient;

    public AuthController(JwtTokenProvider tokenProvider, ReactiveAuthenticationManager authenticationManager, RememberMeService rememberMeService, TrackerClient trackerClient) {
        this.tokenProvider = tokenProvider;
        this.authenticationManager = authenticationManager;
        this.rememberMeService = rememberMeService;
        this.trackerClient = trackerClient;
    }

    @PostMapping("/login")
    public Mono<ResponseEntity<Void>> login(
            @RequestBody AuthenticationRequest authRequest) {

        return this.authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(
                        "", authRequest.apiToken()))
                .onErrorResume(e -> Mono.error(new AccessDeniedException(e.getMessage())))
                .flatMap(auth -> {
                    var accessToken = tokenProvider.createToken(auth);
                    return rememberMeService.rememberMe(auth.getCredentials().toString())
                            .map(rememberMeToken -> new TokenResponse(accessToken, rememberMeToken));
                })
                .map(tokenResponse -> {
                    ResponseEntity.BodyBuilder builder = ResponseEntity.ok()
                            .header(SET_COOKIE, CookieHelper.create(CookieHelper.JWT_COOKIE_NAME,
                                    tokenResponse.accessToken(), CookieHelper.JWT_COOKIE_DURATION).toString());

                    if (tokenResponse.rememberMeToken() != null) {
                        builder.header(SET_COOKIE, CookieHelper.create(CookieHelper.REMEMBER_ME_COOKIE_NAME,
                                tokenResponse.rememberMeToken(), CookieHelper.REMEMBER_ME_COOKIE_DURATION).toString());
                    }

                    return builder.build();
                });

    }

    @GetMapping("/me")
    public Mono<MeResponse> me(@AuthenticationPrincipal UserDetails user) {
        var headers = new HttpHeaders();
        System.out.println("user.getPassword() = " + user.getPassword());
        headers.add("X-TrackerToken", user.getPassword());
        return trackerClient.me(headers, Map.of("fields", "id,email,api_token"))
                .map(me -> new MeResponse(me.id(), me.email()));
    }

    record MeResponse (int id, String email) {
    }

    record TokenResponse(String accessToken, String rememberMeToken) {
    }

}