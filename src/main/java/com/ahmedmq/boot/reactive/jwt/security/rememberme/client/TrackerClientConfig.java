package com.ahmedmq.boot.reactive.jwt.security.rememberme.client;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.support.WebClientAdapter;
import org.springframework.web.service.invoker.HttpServiceProxyFactory;
import reactor.netty.http.client.HttpClient;
import reactor.netty.resources.ConnectionProvider;

import java.time.Duration;

@Configuration
public class TrackerClientConfig {

    @Bean
    TrackerClient trackerClient(WebClient.Builder builder) {
        ConnectionProvider provider = ConnectionProvider.builder("fixed")
                .maxConnections(500)
                .maxIdleTime(Duration.ofSeconds(20))
                .maxLifeTime(Duration.ofSeconds(60))
                .pendingAcquireTimeout(Duration.ofSeconds(60))
                .evictInBackground(Duration.ofSeconds(120)).build();

        HttpClient httpClient = HttpClient.create(provider);
        httpClient.warmup().block();

        var reactorClientHttpConnector = new ReactorClientHttpConnector(httpClient);

        var wc = builder.baseUrl("https://www.pivotaltracker.com/services/v5")
                .clientConnector(reactorClientHttpConnector)
                .build();

        var wca = WebClientAdapter.create(wc);
        return HttpServiceProxyFactory.builder().exchangeAdapter(wca)
                .build()
                .createClient(TrackerClient.class);
    }

}
