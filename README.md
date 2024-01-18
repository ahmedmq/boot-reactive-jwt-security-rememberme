# Spring Security Reactive Login with Remember-Me
<hr/>

Remember-me or persistent-login authentication refers to websites being able to remember the identity of a principal between sessions. Spring Security provides the necessary hooks for these operations for servlet based applications but not for reactive type application ([see github issue](https://github.com/spring-projects/spring-security/issues/5504)). This project demonstrates how to implement persistent Remember-me authentication for a reactive Spring boot app with Spring Security.

# About the application

The application utilizes Pivotal Tracker API for user authentication. When a login request with the Pivotal Tracker API token is received by this application, it in turn calls the Pivotal Tracker API to retrieve user details. If the API token is valid, the spring security context is filled with the fetched user information and two tokens (JWT and Remember-me) are generated and sent back to the client as cookies. The client can use the JWT cookie as a bearer token for subsequent requests, and the Remember-me cookie is stored in the database. The Remember-me cookie is used to authenticate the user for subsequent requests when the JWT cookie is expired.

# Pre-requisites

- Create a Pivotal Tracker [account](https://www.pivotaltracker.com/signup/new)
- Fetch the API token from the [profile](https://www.pivotaltracker.com/profile) page
- Java 21
- Docker to run the app and PostgresSQL database

# Running the application

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


- Run the `curl` command to authenticate with Pivotal Tracker API by providing the correct API Token

    ```bash
    curl -v -X POST http://localhost:8080/auth/login \
       -H 'Content-Type: application/json' \
       -d '{"apiToken":"723SSDF232WWDAOLDPDJM2734DD","rememberMe":true}'
    ```
  The following response is returned containing two cookies: `jwt_token` and `remember_me`. The `jwt_token` is a JWT token that can be used for subsequent requests and has an expiry time of 10 minutes from the issued time. The `remember_me` cookie is a base64 encoded string that contains a unique series id and a token id. The expiry date is set to 7 days from the current date. The `remember_me` cookie is stored in the database.

    ```bash
    * Connected to localhost (::1) port 8080
    > POST /auth/login HTTP/1.1
    > Host: localhost:8080
    > User-Agent: curl/8.4.0
    > Accept: */*
    > Content-Type: application/json
    > Content-Length: 65
    >
    < HTTP/1.1 200 OK
    < Set-Cookie: jwt_token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJUB2bXdhcmUuY29tIiwicm9sZXMiOiJST0xFX1VTRVIiLCJpYXQiOjE3MDU1MTMzMDIsImV4cCI6MTcwNTUxkwMn0.Yezpx634-eeO2rTjtfGa5JVSYbHPkZiF3WxrcX-5HSc; Path=/; Max-Age=600; Expires=Wed, 17 Jan 2024 17:51:42 GMT; Secure; HttpOnly; SameSite=STRICT
    < Set-Cookie: remember_me=MjMwOTU2OGEtY2VmNy00MmQ2LWFmZmUtYTYxZTNmNTQ5YzY3OnNEeTgyeFA5UVV6JTJGR2NMVmZzNkpYUSUzRCUzRA; Path=/; Max-Age=604800; Expires=Wed, 24 Jan 2024 17:41:42 GMT; Secure; HttpOnly; SameSite=STRICT
    < Cache-Control: no-cache, no-store, max-age=0, must-revalidate
    < Pragma: no-cache
    < Expires: 0
    < X-Content-Type-Options: nosniff
    < X-Frame-Options: DENY
    < X-XSS-Protection: 0
    < Referrer-Policy: no-referrer
    < content-length: 0
    ```


- Run the `curl` command to retrieve the user details by providing the `jwt_token` as an Authorization Bearer header

  ```bash
  curl -v -H 'Authorization:Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbXVzaHRhcUB2bXdhcmUuY29tIiwicm9sZXMiOiJST0xFX1VTRVIiLCJ0b2tlbiI6IjczNTJlNTE0N2QwNWU0NDQ3OWJkZDZlNTM0NWU4MmYwIiwiaWF0IjoxNzA1NTcxMjQxLCJleHAiOjE3MDU1NzQ4NDF9.eGnUfTNOAzEXLAskj5amWKKv4PaZEvZc70Od_6Bb0Go' http://localhost:8080/auth/me
  ```
  The token is valid for 10 minutes from the issued time. The following response is returned.
    
  ```json
  {"id":341292344,"email":"test@xyz.com"}
  ```
    
- Run the `curl` command to retrieve the user details by providing the `remember_me` cookie
    
  ```bash
  curl -v --cookie 'remember_me=Mzk3YzBjNGYtN2M2NS00OTUxLTkyMjUtN2UyNjRmZWNlMjU2Ok1UbUxtdm9LdnZIOUNpYjJPZEVJamclM0QlM0Q' http://localhost:8080/auth/me
  ```
  The below is the output of the above command. The `remember_me` cookie is used to authenticate the user even if the JWT cookie is not expired.

  ```json
  {"id":341292344,"email":"test@xyz.com"}
  ```
