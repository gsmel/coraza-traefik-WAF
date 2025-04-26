# Coraza WAF with Traefik Setup

This project implements a Web Application Firewall (WAF) using OWASP Coraza, integrated with Traefik reverse proxy to protect an Ollama API instance. The setup provides enterprise-grade security features while maintaining high performance.

## Components

- **Traefik (v2.10)**: Acts as the reverse proxy and entry point
- **Coraza WAF**: Provides WAF capabilities with ModSecurity-compatible rules
- **Ollama**: Protected API service

## Architecture

```
Client Request → Traefik → Coraza WAF → Ollama API
```

The setup uses Docker Compose to orchestrate three main services:

1. **Traefik**: Handles incoming traffic on ports 80 and 443
2. **Coraza WAF**: Processes requests through port 8080
3. **Ollama**: Runs on internal port 11434

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
├── coraza/
│   └── rules/
│       └── main.conf    # WAF rules configuration
└── traefik/
    └── config/
        └── middleware-chains.yml
```

### Environment Variables

Coraza WAF configuration:
- `CORAZA_PROXY_LISTEN`: WAF listening port (default: :8080)
- `CORAZA_PROXY_UPSTREAM`: Protected service URL
- `CORAZA_RULES_FILE`: Path to rules configuration

## Getting Started

1. Clone this repository
2. Ensure Docker and Docker Compose are installed
3. Start the services:
   ```bash
   docker compose up -d
   ```

## Monitoring

- Traefik dashboard is enabled for monitoring
- WAF audit logs are stored in `/var/log/coraza/audit.log`

## Security Considerations

- The WAF is configured with a default deny policy
- Custom rules can be added to `coraza/rules/main.conf`
- Traefik is configured with security options including `no-new-privileges`

## Version Information

- Traefik: v2.10
- Coraza: Latest stable version
- Based on official OWASP Coraza project (github.com/corazawaf/coraza)
