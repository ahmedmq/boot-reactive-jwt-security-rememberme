package com.ahmedmq.boot.reactive.jwt.security.rememberme.client;

import org.springframework.boot.context.properties.ConfigurationProperties;
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
@ConfigurationProperties(prefix = "github")
public class GithubClientConfig {

    private String host;
    private String version;

    @Bean
    GithubClient githubClient(WebClient.Builder builder) {
        ConnectionProvider provider = ConnectionProvider.builder("fixed")
                .maxConnections(500)
                .maxIdleTime(Duration.ofSeconds(20))
                .maxLifeTime(Duration.ofSeconds(60))
                .pendingAcquireTimeout(Duration.ofSeconds(60))
                .evictInBackground(Duration.ofSeconds(120)).build();

        HttpClient httpClient = HttpClient.create(provider);
        httpClient.warmup().block();

        var reactorClientHttpConnector = new ReactorClientHttpConnector(httpClient);

        var wc = builder.baseUrl(getHost())
                .clientConnector(reactorClientHttpConnector)
                .defaultHeader("Accept", "application/vnd.github+json")
                .defaultHeader("X-GitHub-Api-Version", getVersion())
                .build();

        var wca = WebClientAdapter.create(wc);
        return HttpServiceProxyFactory.builder().exchangeAdapter(wca)
                .build()
                .createClient(GithubClient.class);
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

}
