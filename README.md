# Coraza WAF Middleware for Traefik

This project implements a Web Application Firewall (WAF) using OWASP Coraza as a Forward Auth middleware for Traefik. It provides real-time protection for web applications with automatic rule reloading capabilities.

## Components

- **Traefik (v2.10)**: Acts as the reverse proxy and entry point
- **Coraza WAF (v3.0.0)**: Provides WAF capabilities with ModSecurity-compatible rules
- **OWASP Core Rule Set (CRS)**: Provides base security rules that are automatically managed

## Architecture

```
Client Request → Traefik → Coraza WAF (Forward Auth) → Target Service
```

The setup uses Docker Compose to orchestrate two main services:

1. **Traefik**: Handles incoming traffic on ports 80 and 443
2. **Coraza WAF**: Acts as a Forward Auth service that:
   - Automatically loads and updates CRS rules
   - Supports real-time rule reloading
   - Provides detailed audit logging

## Security Features

The WAF implementation includes:
- Integration with latest OWASP Core Rule Set
- Automatic rule updates via git
- Real-time rule reloading without service restart
- Protection against:
  - SQL Injection
  - Cross-Site Scripting (XSS)
  - Path Traversal
  - Command Injection
  - Remote File Inclusion
  - Protocol Attacks
  - Suspicious User Agents
  - Invalid HTTP Requests
  - Common Web Attacks

## Configuration

### Directory Structure
```
.
├── docker-compose.yml          # Main docker composition
├── Dockerfile                 # Coraza WAF container build
├── scripts/
│   └── update-crs.sh         # CRS update script
└── traefik/
    └── middleware-chains.yml  # Middleware configuration
```

### Rule Management

The system includes automatic management of OWASP Core Rule Set (CRS):
- Rules are automatically downloaded and updated at container startup
- Changes to rule files are detected and reloaded in real-time
- Custom rules can be added to the rules directory

### Environment Variables

Coraza WAF configuration:
- `CORAZA_PROXY_LISTEN`: WAF listening port (default: :8080)

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
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.your-service.rule=Host(`your-domain.com`)"
      - "traefik.http.routers.your-service.middlewares=waf-chain@file"
```

The `waf-chain` middleware includes both WAF protection and secure headers configuration.

## Monitoring and Logging

- Real-time audit logging with detailed request information
- Debug logging level 5 for maximum visibility
- All audit log parts (ABCDEFHIJKZ) enabled for comprehensive logging
- Logs available via Docker:
  ```bash
  docker logs coraza-waf
  ```

## Advanced Features

- **Hot Reload**: Rules are automatically reloaded when modified
- **Secure Headers**: Includes comprehensive security headers configuration
- **Trust Forward Headers**: Properly handles X-Forwarded-* headers
- **Full Request Inspection**: Examines headers, body, and URI components
- **Connection Tracking**: Monitors and logs connection details

## Security Considerations

- Implements secure-by-default configurations
- Includes comprehensive secure headers middleware
- Supports SSL/TLS with configurable policies
- No-new-privileges security option enabled
- All HTTP methods and response codes are monitored
- Detailed audit logging for security events

## Version Information

- Traefik: v2.10
- Coraza: v3.0.0
- Alpine: 3.19 (base image)
- Based on official OWASP Coraza project
