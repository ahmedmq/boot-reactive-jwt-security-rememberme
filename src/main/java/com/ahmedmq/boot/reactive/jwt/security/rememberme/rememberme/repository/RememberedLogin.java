package com.ahmedmq.boot.reactive.jwt.security.rememberme.rememberme.repository;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Version;
import org.springframework.data.relational.core.mapping.Table;

import java.time.LocalDateTime;

@Table(name = "REMEMBERED_LOGINS")
public class RememberedLogin {

    @Id
    private Long id;
    private String apiToken;
    private String series;
    private String tokenLatest;
    private LocalDateTime tokenLatestAt;
    private String tokenPrevious;
    private LocalDateTime tokenPreviousAt;
    @Version
    private Long version;

    public RememberedLogin(String apiToken, String series, String tokenLatest, LocalDateTime tokenLatestAt) {
        this.apiToken = apiToken;
        this.series = series;
        this.tokenLatest = tokenLatest;
        this.tokenLatestAt = tokenLatestAt;
        this.tokenPrevious = null;
        this.tokenPreviousAt = null;
    }

    public RememberedLogin() {
    }

    public Long getId() {
        return id;
    }

    public String getApiToken() {
        return apiToken;
    }

    public String getSeries() {
        return series;
    }

    public String getTokenLatest() {
        return tokenLatest;
    }

    public LocalDateTime getTokenLatestAt() {
        return tokenLatestAt;
    }

    public String getTokenPrevious() {
        return tokenPrevious;
    }

    public LocalDateTime getTokenPreviousAt() {
        return tokenPreviousAt;
    }

    public Long getVersion() {
        return version;
    }

    public void setTokenLatest(String tokenLatest) {
        this.tokenLatest = tokenLatest;
    }

    public void setTokenLatestAt(LocalDateTime tokenLatestAt) {
        this.tokenLatestAt = tokenLatestAt;
    }

    public void setTokenPrevious(String tokenPrevious) {
        this.tokenPrevious = tokenPrevious;
    }

    public void setTokenPreviousAt(LocalDateTime tokenPreviousAt) {
        this.tokenPreviousAt = tokenPreviousAt;
    }

    @Override
    public String toString() {
        return "RememberedLogin{" +
                "id=" + id +
                ", apiToken='" + apiToken + '\'' +
                ", series='" + series + '\'' +
                ", tokenLatest='" + tokenLatest + '\'' +
                ", tokenLatestAt=" + tokenLatestAt +
                ", tokenPrevious='" + tokenPrevious + '\'' +
                ", tokenPreviousAt=" + tokenPreviousAt +
                ", version=" + version +
                '}';
    }
}
