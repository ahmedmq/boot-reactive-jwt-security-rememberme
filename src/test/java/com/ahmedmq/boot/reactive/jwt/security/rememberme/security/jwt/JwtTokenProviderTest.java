package com.ahmedmq.boot.reactive.jwt.security.rememberme.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

class JwtTokenProviderTest {

    private final Logger log = org.slf4j.LoggerFactory.getLogger(JwtTokenProviderTest.class);

    private static final String TEST_USER = "user";

    private static final String TEST_ROLE_NAME = "ROLE_USER";

    private JwtTokenProvider jwtTokenProvider;
    private JwtProperties properties;

    @BeforeEach
    void setup() {
        this.properties = new JwtProperties("ecf1222c-88fd-47f3-988f-bdd78bade1ad", 10000);
        this.jwtTokenProvider = new JwtTokenProvider(this.properties);

        assertThat(this.jwtTokenProvider).isNotNull();
        this.jwtTokenProvider.init();
    }

    @Test
    void testGenerateAndParseToken() {
        String token = generateToken(TEST_USER, TEST_ROLE_NAME);
        var auth = this.jwtTokenProvider.getAuthentication(token);
        var principal = (UserDetails) auth.getPrincipal();
        assertThat(principal.getUsername()).isEqualTo(TEST_USER);
        assertThat(
                principal.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toList())
        ).contains(TEST_ROLE_NAME);
    }

    @Test
    void testGenerateAndParseToken_withoutRoles() {
        String token = generateToken(TEST_USER);
        var auth = this.jwtTokenProvider.getAuthentication(token);
        var principal = (UserDetails) auth.getPrincipal();
        assertThat(principal.getUsername()).isEqualTo(TEST_USER);
        assertThat(principal.getAuthorities()).isEmpty();
    }

    @Test
    void testParseTokenException() {
        String token = "anunknowtokencannotbeparsedbyjwtprovider";
        Assertions.assertThatExceptionOfType(JwtException.class)
                .isThrownBy(() -> this.jwtTokenProvider.getAuthentication(token));
    }

    @Test
    void testValidateTokenException_failed() {
        String token = "anunknowtokencannotbeparsedbyjwtprovider";
        assertThat(this.jwtTokenProvider.validateToken(token)).isFalse();
    }

    @Test
    void testValidateExpirationDate() {
        var secret = Base64.getEncoder().encodeToString(this.properties.secretKey().getBytes());
        var secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));

        Claims claims = Jwts.claims().subject(TEST_USER).build();
        Date now = new Date();
        Date validity = new Date(now.getTime() - 1);

        var expiredToken = Jwts.builder()
                .claims(claims)
                .issuedAt(now)
                .expiration(validity)
                .signWith(secretKey, Jwts.SIG.HS256)
                .compact();

        assertThat(this.jwtTokenProvider.validateToken(expiredToken)).isFalse();
    }

    @Test
    void testValidateTokenException() {
        String token = generateToken(TEST_USER, TEST_ROLE_NAME);
        assertThat(this.jwtTokenProvider.validateToken(token)).isTrue();
    }

    private String generateToken(String username, String... roles) {
        Collection<? extends GrantedAuthority> authorities = AuthorityUtils.createAuthorityList(roles);
        var principal = new User(username, "password", authorities);
        var usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(principal, null, authorities);
        return this.jwtTokenProvider.createToken(usernamePasswordAuthenticationToken);
    }

}