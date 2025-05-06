# Build stage
FROM golang:1.22-alpine AS builder

# Install build dependencies
RUN apk add --no-cache build-base git pcre2-dev pkgconfig

# Set working directory
WORKDIR /app

# Copy the source code
COPY . .

# Force module initialization with specific versions and download dependencies
RUN go mod edit -go=1.22 && \
    go get github.com/corazawaf/coraza/v3@v3.1.0 && \
    go get github.com/corazawaf/coraza/v3/types@v3.1.0 && \
    go get github.com/fsnotify/fsnotify@v1.7.0 && \
    go get github.com/prometheus/client_golang/prometheus@v1.19.0 && \
    go get github.com/prometheus/client_golang/prometheus/promhttp@v1.19.0 && \
    go mod tidy

# Build the WAF
RUN CGO_ENABLED=1 go build -v -ldflags="-s -w" -o coraza-waf

# Create final image
FROM alpine:3.18

# Install runtime dependencies
RUN apk add --no-cache ca-certificates pcre2 pcre2-dev

# Set up rules directory (don't attempt to copy files that may not exist)
RUN mkdir -p /etc/coraza/rules

# Copy binary from builder
COPY --from=builder /app/coraza-waf /usr/local/bin/coraza-waf

# Add a basic example rule (fixed quoting syntax)
RUN echo "SecRule REQUEST_URI \"@contains /admin\" \"id:1000,phase:1,deny,status:403,msg:'Admin access blocked'\"" > /etc/coraza/rules/basic-rules.conf

# Define environment variables with defaults
ENV CORAZA_PROXY_LISTEN=:9080
ENV CORAZA_RULES_DIR=/etc/coraza/rules
ENV CORAZA_METRICS_LISTEN=:9090

# Expose the service port
EXPOSE 9080 9090

# Run the WAF
ENTRYPOINT ["/usr/local/bin/coraza-waf"]
