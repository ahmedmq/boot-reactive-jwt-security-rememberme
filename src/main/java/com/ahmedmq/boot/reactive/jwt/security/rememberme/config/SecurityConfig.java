package com.ahmedmq.boot.reactive.jwt.security.rememberme.config;

import com.ahmedmq.boot.reactive.jwt.security.rememberme.client.GithubClient;
import com.ahmedmq.boot.reactive.jwt.security.rememberme.core.filter.PersistentRememberMeAuthenticationFilter;
import com.ahmedmq.boot.reactive.jwt.security.rememberme.core.service.RememberMeService;
import com.ahmedmq.boot.reactive.jwt.security.rememberme.security.jwt.JwtTokenAuthenticationFilter;
import com.ahmedmq.boot.reactive.jwt.security.rememberme.security.jwt.JwtTokenProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;

@Configuration
public class SecurityConfig {

    @Bean
    SecurityWebFilterChain springWebFilterChain(ServerHttpSecurity http,
                                                JwtTokenProvider tokenProvider,
                                                ReactiveAuthenticationManager reactiveAuthenticationManager,
                                                RememberMeService rememberMeService) {

        return http.csrf(ServerHttpSecurity.CsrfSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .authenticationManager(reactiveAuthenticationManager)
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
                .authorizeExchange(it -> it
                        .pathMatchers("/auth/login").permitAll()
                        .anyExchange().authenticated()
                )
                .addFilterAt(new JwtTokenAuthenticationFilter(tokenProvider),
                        SecurityWebFiltersOrder.HTTP_BASIC)
                .addFilterAfter(new PersistentRememberMeAuthenticationFilter(rememberMeService),
                        SecurityWebFiltersOrder.HTTP_BASIC)
                .build();
    }

    @Bean
    public ReactiveAuthenticationManager reactiveAuthenticationManager(GithubClient githubClient) {
        return authentication -> {
            String personalAccessToken = authentication.getCredentials().toString();
            var headers = new HttpHeaders();
            headers.setBearerAuth(personalAccessToken);
            return githubClient.user(headers)
                    .map(me -> {
                        UserDetails userDetails = User
                                .withUsername(me.login()).password(personalAccessToken)
                                .authorities("ROLE_USER")
                                .accountExpired(false)
                                .credentialsExpired(false)
                                .disabled(false)
                                .accountLocked(false)
                                .build();
                        return UsernamePasswordAuthenticationToken.authenticated(userDetails,
                                userDetails.getPassword(), userDetails.getAuthorities());
                    });

        };
    }
}
