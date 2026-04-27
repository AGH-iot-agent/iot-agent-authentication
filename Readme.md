# IoT Agent Authentication API

## Description
IoT Agent Authentication API is a microservice responsible for handling authentication and authorization in the IoT system. It manages user credentials, token validation, and integration with external identity providers.

## Features
- User authentication and authorization
- Token validation (e.g., JWT)
- Integration with databases and external identity providers (e.g., Keycloak)
- Secure endpoints for other IoT microservices

## Requirements
- Java 21
- Maven
- PostgreSQL database (or any JDBC-compatible database)

The application listens on port 8080 by default.

## Configuration
The configuration file is located at `src/main/resources/application.yml`.

## Example Endpoints
- `POST /auth/login` – user login
- `POST /auth/refresh` – refresh authentication token
- `GET /auth/validate` – validate token

## Deployment
The application includes Helm charts (`Helm/values-dev.yaml`, `Helm/values-sbx.yaml`) and a Dockerfile for containerized deployments.
