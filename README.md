# Spring Security Reactive Login with Remember-Me
<hr/>

Remember-me or persistent-login authentication refers to websites being able to remember the identity of a principal between sessions. [Spring Security](https://docs.spring.io/spring-security/reference/servlet/authentication/rememberme.html) provides the necessary hooks for these operations for servlet based applications but not for reactive type application ([see github issue](https://github.com/spring-projects/spring-security/issues/5504)). This project demonstrates how to implement persistent Remember-me authentication for a reactive Spring boot app with Spring Security.

## About the application

The application utilizes GitHub REST API for user authentication. When a login request with the GitHub Personal Access token is received by this application, it in turn calls the GitHub REST API to retrieve the user details associated with the token. If the API token is valid, the spring security context is populated with the fetched user information and two tokens (JWT and Remember-me) are generated and sent back to the client as cookies. The client can use the JWT (Json Web Token) cookie as a bearer token for subsequent requests, and the Remember-me cookie is stored in the database. The Remember-me cookie is used to authenticate the user for subsequent request when the JWT token is expired.

## Pre-requisites

- Create a GitHub Personal Access [Token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens#creating-a-personal-access-token-classic)
- Java 21
- Docker to run the app and PostgresSQL database

## Running the application

- From the root of the project, run the [docker-compose.yml](docker-compose.yml) file to start the application and PostgresSQL database

    ```bash
    docker compose up -d
    ```
  The following output is displayed when the containers are started successfully.

    ```text
    [+] Running 3/3
     ✔ Network boot-reactive-jwt-security-rememberme_app_nw  Created                                                                                                                                                              0.0s 
     ✔ Container postgres                                    Healthy                                                                                                                                                             10.7s 
     ✔ Container app                                         Started      
    ```
    During startup the database is initialized with a single table ([schema.sql](src/main/resources/schema.sql)) to store the Remember-me cookie details.


- Run the `curl` command to authenticate with GitHub REST API by providing the correct API Token and the `rememberMe` flag set to true

    ```bash
    curl -v -X POST http://localhost:8080/auth/login \
       -H 'Content-Type: application/json' \
       -d '{"personalAccessToken":"ghp_hrshOO2323N86Xu7csfscDlT688Y10Mv0esdH2","rememberMe":true}'
    ```
  The following response is returned containing two cookies: `jwt_token` and `remember_me`. 

    ```text
    * Connected to localhost (::1) port 8080
    > POST /auth/login HTTP/1.1
    > Host: localhost:8080
    > User-Agent: curl/8.4.0
    > Accept: */*
    > Content-Type: application/json
    > Content-Length: 65
    >
    < HTTP/1.1 200 OK
    < Set-Cookie: jwt_token=eyJhbGciOiJIUzI1NiJ9.eyJzdWiOiJUB2bXdhcmUuY29tIiwicm9sZXMiOiJST0xFX1VTRVIiLCJpYXQiOjE3MDU1MTMzMDIsImV4cCI6MTcwNTUxkwMn0.Yezpx634-eeO2rTjtfGa5JVSYbHPkZiF3WxrcX-5HSc; Path=/; Max-Age=600; Expires=Wed, 17 Jan 2024 17:51:42 GMT; Secure; HttpOnly; SameSite=STRICT
    < Set-Cookie: remember_me=MjMwOTU2OGEt2VmNy00MmQ2LWFmZmUtYTYxZTNmNTQ5YzY3OnNEeTgyeFA5UVV6JTJGR2NMVmZzNkpYUSUzRCUzRA; Path=/; Max-Age=604800; Expires=Wed, 24 Jan 2024 17:41:42 GMT; Secure; HttpOnly; SameSite=STRICT
    < Cache-Control: no-cache, no-store, max-age=0, must-revalidate
    < Pragma: no-cache
    < Expires: 0
    < X-Content-Type-Options: nosniff
    < X-Frame-Options: DENY
    < X-XSS-Protection: 0
    < Referrer-Policy: no-referrer
    < content-length: 0
    ```
  The `jwt_token` is a JWT token that can be used for subsequent requests and has an expiry time of 10 minutes from the issued time. The `remember_me` cookie is a base64 encoded string that contains a unique series id and a token id. The expiry date is set to 7 days from the current date. The `remember_me` cookie is stored in the database.


- Run the `curl` command to retrieve the user details by providing the `jwt_token` as an Authorization Bearer header

  ```bash
  curl -v -H 'Authorization:Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWiOiJhbXVzaHRhcUB2bXdhcmUuY29tIiwicm9sZXMiOiJST0xFX1VTRVIiLCJ0b2tlbiI6IjczNTJlNTE0N2QwNWU0NDQ3OWJkZDZlNTM0NWU4MmYwIiwiaWF0IjoxNzA1NTcxMjQxLCJleHAiOjE3MDU1NzQ4NDF9.eGnUfTNOAzEXLAskj5amWKKv4PaZEvZc70Od_6Bb0Go' http://localhost:8080/auth/user
  ```
  The user details are returned as JSON response:
    
  ```json
  {"id":30720533,"login":"ethan","name":"Ethan Hunt"}
  ```
    
- Run the `curl` command to retrieve the user details by providing only the `remember_me` cookie
    
  ```bash
  curl -v --cookie 'remember_me=Mzk3YzBjNGYtN2M2NS00OTUxLTkyMjUtN2UyNjRmZWNlMjU2Ok1UbUxtdm9LdnZIOUNpYjJPZEVJamclM0QlM0Q' http://localhost:8080/auth/user
  ```
  The below is the output of the above command. 

  ```text
  *   Trying [::1]:8080...
  * Connected to localhost (::1) port 8080
    > GET /auth/user HTTP/1.1
    > Host: localhost:8080
    > User-Agent: curl/8.4.0
    > Accept: */*
    > Cookie: remember_me=NzkwNWZlMWMtMTBmYy00NDRjLWFkMTUtN2UzNGFlNzhkZTkzOnhZWmNxd0ZZYUFDYiUyRnNvMWJyc1VCUSUzRCUzRA
    >
  < HTTP/1.1 200 OK
  < Content-Type: application/json
  < Content-Length: 56
  < Cache-Control: no-cache, no-store, max-age=0, must-revalidate
  < Pragma: no-cache
  < Expires: 0
  < X-Content-Type-Options: nosniff
  < X-Frame-Options: DENY
  < X-XSS-Protection: 0
  < Referrer-Policy: no-referrer
  < Set-Cookie: remember_me=NzkwNWZlMWMtMTBmYy00NDRjLWFkMTUtN2UzNGFlNzhkZTkzOkhKNzNnNiUyRm50TjNXVDFPQXVtNU8xQSUzRCUzRA; Path=/; Max-Age=604800; Expires=Fri, 26 Jan 2024 16:08:31 GMT; Secure; HttpOnly; SameSite=STRICT
  < Set-Cookie: jwt_token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhaG1lZG1xIiwicm9sZXMiOiJST0xFX1VTRVIiLCJ0b2tlbiI6ImdocF9ocnNoT09Td2lOODZYdTdjQ0djRGxUNjg4WTEwTXYwZUpGSDIiLCJpYXQiOjE3MDU2ODA1MTEsImV4cCI6MTcwNTY4NDExMX0.rm4Au5rdfnNhPgnntKFyd50wXMYbIPxNoVJXbs2P3J0; Path=/; Max-Age=600; Expires=Fri, 19 Jan 2024 16:18:31 GMT; Secure; HttpOnly; SameSite=STRICT
  <
  * Connection #0 to host localhost left intact
    {"id":30720533,"login":"ethan","name":"Ethan Hunt"}
    ```
  The `remember_me` cookie is used to authenticate the user even if the JWT cookie is not expired.  Notice a new `jwt_token` is sent back as cookie which the client can use for subsequent requests.

## Notes

- The main class for the reactive persistent remember-me authentication is [PersistentRememberMeService](src/main/java/com/ahmedmq/boot/reactive/jwt/security/rememberme/core/service/PersistentRememberMeService.java). The implementation of this class closely resembles the servlet implementation of persistent remember-me authentication in [PersistentTokenBasedRememberMeServices.java](https://github.com/spring-projects/spring-security/blob/main/web/src/main/java/org/springframework/security/web/authentication/rememberme/PersistentTokenBasedRememberMeServices.java)
- The GitHub Personal Access token is currently stored in the JWT. This is not a good practice and is only implemented here for demonstration purposes. 
