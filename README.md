# Coraza WAF Middleware for Traefik

This project implements a Web Application Firewall (WAF) using [OWASP Coraza](https://coraza.io) as a Forward Auth middleware for Traefik. It provides real-time protection for web applications with automatic rule reloading capabilities.

## Components

- **Traefik (v3.3.5)**: Acts as the reverse proxy and entry point
- **Coraza WAF (v3.0.0)**: Provides WAF capabilities with ModSecurity-compatible rules
- **OWASP Core Rule Set (CRS)**: Provides base security rules that are automatically managed
- **Prometheus Metrics**: Detailed WAF metrics for monitoring and analysis


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
   - Exports Prometheus metrics for monitoring


## Security Features

The WAF implementation includes:
- Integration with latest [OWASP Core Rule Set](https://github.com/coreruleset/coreruleset/tree/main)
- Automatic rule updates from [OWASP CRS](https://github.com/coreruleset/coreruleset/tree/main/rules)
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
├── Dockerfile                  # Coraza WAF container build
├── go.mod                      # Go module dependencies
├── main.go                     # Main WAF application code
├── coraza/
│   └── rules/                  # WAF rules directory (auto-managed)
├── scripts/
│   └── update-crs.sh           # CRS update script
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
- `CORAZA_PROXY_LISTEN`: WAF listening port (default: :9080)

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

## Monitoring and Metrics

### Prometheus Metrics

The WAF exports detailed Prometheus metrics at the `/metrics` endpoint. The following metrics are available:

- **coraza_requests_total**: Total number of requests processed by the WAF
  - Labels: `status`, `method`, `path`, `destination`, `rule_id`, `source_ip`, `page_load_id`

- **coraza_rule_matches_total**: Total number of rule matches by rule ID
  - Labels: `rule_id`, `severity`, `method`, `path`, `destination`, `message`, `source_ip`, `page_load_id`

- **coraza_request_duration_seconds**: Request duration in seconds (histogram)
  - Labels: `status`, `destination`, `rule_id`, `source_ip`, `page_load_id`

### Grafana Dashboards

A comprehensive Grafana dashboard is available to visualize WAF metrics:

1. **WAF Overview Dashboard**: Shows general traffic patterns and rule matches
2. **Advanced Traffic Analysis Dashboard**: Detailed analysis including page load metrics
   - Visualizes requests per page load
   - Shows distribution of traffic across services
   - Displays rule match patterns
   - Includes live traffic logs

To import these dashboards:
1. Go to Grafana → Dashboards → Import
2. Paste the dashboard JSON (available in the repository)
3. Select your Prometheus data source
4. Click Import

### Page Load Tracking

To group and analyze requests by actual page loads, this WAF supports a `X-Page-Load-ID` header. All Prometheus metrics include a `page_load_id` label, allowing you to correlate all requests belonging to a single page load.

#### How to Use

1. **Inject a Unique Page Load ID in the Browser**
   Add the following JavaScript snippet to your web application. It generates a unique ID for each page load and sends it as a custom header with every request:

   ```js
   (function() {
     const pageLoadId = self.crypto.randomUUID ? self.crypto.randomUUID() : Math.random().toString(36).slice(2) + Date.now();
     const origOpen = XMLHttpRequest.prototype.open;
     XMLHttpRequest.prototype.open = function() {
       origOpen.apply(this, arguments);
       this.setRequestHeader('X-Page-Load-ID', pageLoadId);
     };
     if (window.fetch) {
       const origFetch = window.fetch;
       window.fetch = function(input, init = {}) {
         init.headers = init.headers || {};
         if (init.headers instanceof Headers) {
           init.headers.set('X-Page-Load-ID', pageLoadID);
         } else {
           init.headers['X-Page-Load-ID'] = pageLoadId;
         }
         return origFetch(input, init);
       };
     }
   })();
   ```
   
   For static resources (images, CSS, etc.), you can append the ID as a query parameter or use a Service Worker for advanced use cases.

2. **Grafana Usage**
   - In your Prometheus queries, use the `page_load_id` label to group requests by page load.
   - Example: `sum by (page_load_id) (coraza_requests_total)`

3. **Fallback**
   - If the header is missing, metrics will use `page_load_id="none"`.

## Logging

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
- **Page Load Tracking**: Groups requests by page load for better analytics

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
- Last Updated: April 2025

