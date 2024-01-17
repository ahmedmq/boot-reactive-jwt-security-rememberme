CREATE TABLE IF NOT EXISTS REMEMBERED_LOGINS
(
    ID BIGSERIAL PRIMARY KEY,
    API_TOKEN VARCHAR(64) NOT NULL,
    SERIES  VARCHAR(64) NOT NULL,
    TOKEN_LATEST VARCHAR(64) NOT NULL,
    TOKEN_LATEST_AT TIMESTAMP NOT NULL,
    TOKEN_PREVIOUS VARCHAR(64) ,
    TOKEN_PREVIOUS_AT TIMESTAMP,
    VERSION INTEGER NOT NULL
);
