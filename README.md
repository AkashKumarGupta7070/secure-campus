# Secure Campus 

Backend system for a **Secure Campus Security Monitoring System** built using **Spring Boot**.

## Tech Stack

- Java 17
- Spring Boot
- Spring Security
- JWT Authentication
- MySQL
- Spring Data JPA
- Maven
- Postman (API Testing)
- Git & GitHub (Version Control)

## Features Implemented

### Authentication
- User login with Spring Security
- BCrypt password encryption
- JWT access tokens
- Refresh token system
- Refresh token rotation

### Authorization
- Role-based access control (RBAC)
- Secure API endpoints using Spring Security
- Protected routes for authenticated users

### Security Monitoring
- Track login attempts
- Detect repeated failed logins
- Monitor suspicious access attempts
- Log authentication activities

### Intrusion Detection Rules
- Detect multiple failed login attempts
- Detect unauthorized access to restricted endpoints
- Identify abnormal request patterns
- Generate alerts for suspicious behaviour

### Logging & Monitoring
- Record authentication events
- Maintain structured security logs
- Track user activity within the system

## Installation

Clone the repository:

```bash
git clone https://github.com/AkashKumarGupta7070/secure-campus.git
```

Navigate into the project folder:

```bash
cd secure-campus
```

Configure MySQL database in:

```
src/main/resources/application.properties
```

Run the application:

```bash
./mvnw spring-boot:run
```

or (Windows)

```bash
mvnw.cmd spring-boot:run
```

## API Testing

The APIs can be tested using **Postman**.

Typical workflow:

1. Register a user
2. Login to receive a JWT token
3. Use the token to access protected endpoints
4. Monitor logs for suspicious activity detection

## Team

- **Akash Kumar Gupta** — Backend Developer & Security Integration Lead
- **Bittu Kumar** — Security Analyst & Threat Modelling Lead
- **Priyanshu Sharma** — Documentation & Research Coordinator
- **Yash Kumar** — Frontend Developer & Dashboard Designer

## Project Conclusion

The goal of Secure Campus is to build a **lightweight security monitoring system for campus platforms** that can detect suspicious activities even after successful login, helping administrators identify potential insider threats and unauthorized access within campus systems.
