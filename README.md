# Coraza WAF Middleware for Traefik

This project implements a Web Application Firewall (WAF) using OWASP Coraza as a Forward Auth middleware for Traefik. This setup allows you to add WAF protection to any service in your Traefik configuration.

## Components

- **Traefik (v2.10)**: Acts as the reverse proxy and entry point
- **Coraza WAF**: Provides WAF capabilities as a Forward Auth middleware with ModSecurity-compatible rules

## Architecture

```
Client Request → Traefik → Coraza WAF (Forward Auth) → Target Service
```

The setup uses Docker Compose to orchestrate two main services:

1. **Traefik**: Handles incoming traffic on ports 80 and 443
2. **Coraza WAF**: Acts as a Forward Auth service on port 8080

## Security Features

The WAF implementation includes protection against:
- SQL Injection
- Cross-Site Scripting (XSS)
- Path Traversal
- Command Injection
- Suspicious User Agents
- Invalid Content Types

## Configuration

### Directory Structure
```
.
├── docker-compose.yml    # Main docker composition
├── Dockerfile           # Coraza WAF container build
└── rules/
    └── main.conf    # WAF rules configuration
└── traefik/
    └── middleware-chains.yml  # Middleware configuration
```

### Environment Variables

Coraza WAF configuration:
- `CORAZA_PROXY_LISTEN`: WAF listening port (default: :8080)
- `CORAZA_RULES_FILE`: Path to rules configuration

## Usage

### Getting Started

1. Clone this repository
2. Ensure Docker and Docker Compose are installed
3. Start the services:
   ```bash
   docker compose up -d
   ```

### Protecting Your Services

To protect any service with the WAF, add the middleware to your service's Traefik labels:

```yaml
services:
  your-service:
    # ... your service configuration ...
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.your-service.rule=Host(`your-domain.com`)"
      - "traefik.http.routers.your-service.middlewares=waf-chain@file"
```

## Monitoring

- Traefik dashboard is enabled for monitoring
- WAF audit logs are printed to stdout and can be viewed using:
  ```bash
  docker logs coraza-waf
  ```
- Audit logs include details of blocked requests and security rule violations

## Security Considerations

- The WAF is configured with a default deny policy
- Custom rules can be added to `coraza/rules/main.conf`
- Traefik is configured with security options including `no-new-privileges`
- All request headers are inspected for potential threats

## Version Information

- Traefik: v2.10
- Coraza: v3.0.0
- Based on official OWASP Coraza project (github.com/corazawaf/coraza)
