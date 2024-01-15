package com.ahmedmq.boot.reactive.jwt.security.rememberme;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class BootReactiveJwtSecurityRemembermeApplication {

	public static void main(String[] args) {
		SpringApplication.run(BootReactiveJwtSecurityRemembermeApplication.class, args);
	}

}
