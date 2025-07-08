# Coraza WAF 🛡️

A simple, powerful Web Application Firewall using [OWASP Coraza](https://coraza.io) with essential security rules to protect your web applications.

## ✨ Features

- 🔒 **Essential OWASP Protection** - Blocks SQL injection, XSS, RCE, and more
- ⚡ **Real-time Blocking** - Instant protection against malicious requests  
- 📊 **Monitoring Ready** - Built-in Prometheus metrics
- 🐳 **Docker Native** - Easy deployment with Docker Compose
- 🔧 **Easy Integration** - Works with Traefik, Nginx, Apache

## 🚀 Quick Start

```bash
# Download and run
git clone https://github.com/gsmel/coraza-traefik-WAF
cd coraza-traefik-WAF
docker compose up -d --build
```

## ✅ Test Protection

```bash
# Normal request (should work)
curl http://localhost:9080

# Malicious request (should be blocked)
curl -d "hack=<script>alert('xss')</script>" http://localhost:9080
# Response: Forbidden

# View metrics
curl http://localhost:9090/metrics
```

## 🔧 Integration

Choose your reverse proxy:

### Traefik
See `integrations/traefik-middleware.yml` for complete setup.

### Nginx  
See `integrations/nginx-auth.conf` for configuration.

### Apache
See `integrations/apache-proxy.conf` for configuration.

## 📁 Project Structure

```
├── docker-compose.yml    # Main deployment
├── Dockerfile           # WAF container  
├── main.go             # WAF application
├── rules/              # OWASP security rules
├── integrations/       # Reverse proxy configs
│   ├── traefik-middleware.yml
│   ├── nginx-auth.conf
│   └── apache-proxy.conf
├── LICENSE             # Apache 2.0 license
└── .gitignore         # Git ignore rules
```

## 🔍 Monitoring

- **Logs**: `docker compose logs -f coraza`
- **Metrics**: http://localhost:9090/metrics
- **Status**: `docker ps | grep coraza`

## 🛠️ Customization

Edit `rules/crs-setup.conf` to adjust:
- Security strictness (paranoia level)
- Blocking thresholds  
- Custom exclusions

Restart after changes: `docker compose restart`

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

Licensed under the Apache License 2.0 - see [LICENSE](LICENSE) file.

## 🆘 Support

- [Coraza Documentation](https://coraza.io/docs/)
- [OWASP CRS](https://coreruleset.org/docs/)
- [Issues](https://github.com/gsmel/coraza-traefik-WAF/issues)

- Traefik: v2.10
- Coraza: v3.0.0
- Alpine: 3.19 (base image)
- Based on official OWASP Coraza project
- Last Updated: April 2025
