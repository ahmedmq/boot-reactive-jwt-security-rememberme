# Spring Security Reactive with Remember Me

Remember-me or persistent-login authentication refers to websites being able to remember the identity of a principal between sessions. Spring Security provides the necessary hooks for these operations for servlet based applications but [not](https://github.com/spring-projects/spring-security/issues/5504) for reactive type application. This project demonstrates how to implement persistent Remember-me authentication for a reactive Spring boot app using PostgresSQL database.

# About the application

The application utilizes Pivotal Tracker for user authentication. When a login request with the Pivotal Tracker API token is received, the application calls the Pivotal Tracker API to retrieve user details. If the API token is valid, the spring security context is filled with the user information, and two tokens (JWT and Remember-me token) are generated and sent back to the client. The client can use the JWT token for subsequent requests, and the Remember-me token is stored in the database. The Remember-me token is used to authenticate the user for subsequent requests when the JWT token is expired.

# Pre-requisites

- Create a Pivotal Tracker [account](https://www.pivotaltracker.com/signup/new)
- Fetch the API token from the [profile](https://www.pivotaltracker.com/profile) page
- Java 17
- Docker to run the app and PostgresSQL database



