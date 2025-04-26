# Build stage
FROM golang:1.23-alpine AS builder

# Install required build tools
RUN apk add --no-cache git make

# Clone Coraza repository
WORKDIR /src
RUN git clone https://github.com/corazawaf/coraza.git .

# Build the http-server example which includes a full WAF implementation
WORKDIR /src/examples/http-server
RUN go build -o /coraza-waf

# Final stage
FROM alpine:3.19

# Copy binary and set up directories
COPY --from=builder /coraza-waf /app/coraza-waf
RUN mkdir -p /etc/coraza/rules /app/config /var/log/coraza && \
    cd /app/config && \
    ln -s /etc/coraza/rules/main.conf default.conf && \
    chmod 755 /var/log/coraza

# Set working directory
WORKDIR /app/config

# Expose the default port
EXPOSE 8080

# Set environment variables with defaults
ENV CORAZA_PROXY_LISTEN=":8080" \
    CORAZA_RULES_FILE="/etc/coraza/rules/main.conf"

CMD ["/app/coraza-waf"]