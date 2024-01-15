package com.ahmedmq.boot.reactive.jwt.security.rememberme.security.jwt;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import static org.assertj.core.api.Assertions.assertThat;


@SpringBootTest
@TestPropertySource(properties = {
        "jwt.secretKey=ecf1222c-88fd-47f3-988f-bdd78bade1ad",
        "jwt.validityInMs=10000"
})
class JwtPropertiesTest {

    @Autowired
    private JwtProperties jwtProperties;

    @Test
    void testProperties() {
        assertThat(jwtProperties.secretKey()).isEqualTo("ecf1222c-88fd-47f3-988f-bdd78bade1ad");
        assertThat(jwtProperties.validityInMs()).isEqualTo(10000);
    }
}