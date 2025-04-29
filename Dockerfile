# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Install required build dependencies with correct package names
RUN apk add --no-cache \
    git \
    make \
    gcc \
    musl-dev \
    pkgconfig \
    build-base \
    pcre2-dev \
    pcre2

# Copy Go files
COPY go.mod main.go ./

# Initialize modules and download dependencies
RUN go mod init coraza-forward-auth || true && \
    go get github.com/corazawaf/coraza/v3@v3.1.0 && \
    go get github.com/fsnotify/fsnotify@v1.7.0 && \
    go get github.com/prometheus/client_golang@v1.19.0 && \
    go mod tidy

# Build with verbose output and specific PCRE2 configuration
RUN PKG_CONFIG_PATH=/usr/lib/pkgconfig \
    CGO_ENABLED=1 \
    CGO_CFLAGS="`pkg-config --cflags libpcre2-8`" \
    CGO_LDFLAGS="`pkg-config --libs libpcre2-8`" \
    GOEXPERIMENT=cgocheck2 \
    go build -v -o coraza-waf

# Final stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache \
    git \
    pcre2 \
    ca-certificates

# Copy binary and set up directories
COPY --from=builder /app/coraza-waf /app/coraza-waf
COPY scripts/update-crs.sh /app/update-crs.sh
RUN mkdir -p /etc/coraza/rules && \
    chmod +x /app/update-crs.sh

WORKDIR /app

EXPOSE 9080

ENV CORAZA_PROXY_LISTEN=":9080"

# Initialize CRS rules and start WAF
CMD ["/bin/sh", "-c", "/app/update-crs.sh && /app/coraza-waf"]
