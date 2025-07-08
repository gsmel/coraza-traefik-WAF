# Build stage
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache build-base git pcre2-dev pkgconfig

# Set working directory
WORKDIR /app

# Copy the source code
COPY . .

# Download dependencies and tidy
RUN go mod tidy && \
    go mod download

# Build the WAF
RUN CGO_ENABLED=1 go build -v -ldflags="-s -w" -o coraza-waf

# Create final image
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache ca-certificates pcre2 pcre2-dev

# Set up rules directory and copy rules
RUN mkdir -p /etc/coraza/rules
COPY rules/ /etc/coraza/rules/

# Copy binary
COPY --from=builder /app/coraza-waf /usr/local/bin/coraza-waf

# Environment variables
ENV CORAZA_PROXY_LISTEN=:9080
ENV CORAZA_RULES_DIR=/etc/coraza/rules
ENV CORAZA_METRICS_LISTEN=:9090

# Expose the service ports
EXPOSE 9080 9090

# Create entrypoint script properly
RUN printf '#!/bin/sh\nset -e\n\nexec /usr/local/bin/coraza-waf -listen "$CORAZA_PROXY_LISTEN" -rules "$CORAZA_RULES_DIR" -metrics "$CORAZA_METRICS_LISTEN"\n' > /usr/local/bin/entrypoint.sh && \
    chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
