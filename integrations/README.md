# Integration Examples

This directory contains configuration examples for integrating Coraza WAF with popular reverse proxies.

## Files

- `traefik-middleware.yml` - Traefik dynamic configuration for ForwardAuth middleware
- `nginx-auth.conf` - Nginx auth_request module configuration  
- `apache-proxy.conf` - Apache mod_proxy configuration with authentication

## Quick Setup

1. Choose your reverse proxy configuration file
2. Modify the example to match your domain and service names
3. Ensure the Coraza WAF container is accessible from your reverse proxy
4. Test the configuration with normal and malicious requests

## Notes

- All examples assume the WAF is running on `coraza-waf:9080`
- Adjust hostnames, ports, and networks to match your setup
- The WAF metrics endpoint is available at `/metrics` (restrict access in production)
- Enable proper logging and monitoring for security events

For detailed setup instructions, see the main [README](../README.md).
