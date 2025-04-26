# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /app
RUN apk add --no-cache git make

# Create a simple forward auth WAF service
COPY <<EOF /app/main.go
package main

import (
    "fmt"
    "log"
    "net/http"
    "os"
    "strings"
    "github.com/corazawaf/coraza/v3"
)

func main() {
    // Configure logging to include timestamp
    log.SetFlags(log.LstdFlags | log.Lmicroseconds)

    // Initialize Coraza WAF with audit logging
    config := coraza.NewWAFConfig()
    
    // Add directives as a single string
    directives := `
    Include ` + os.Getenv("CORAZA_RULES_FILE") + `
    SecAuditEngine RelevantOnly
    SecAuditLog /dev/stdout
    SecAuditLogParts ABCFHZ
    SecAuditLogRelevantStatus "^[45]"
    `
    config = config.WithDirectives(directives)

    waf, err := coraza.NewWAF(config)
    if err != nil {
        log.Fatal(err)
    }

    // Forward auth handler
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        tx := waf.NewTransaction()
        defer func() {
            if tx != nil {
                tx.ProcessLogging()
                tx.Close()
            }
        }()

        // Split remote address into host and port
        remoteAddr := r.RemoteAddr
        remoteHost := remoteAddr
        remotePort := 0
        if idx := strings.LastIndex(remoteAddr, ":"); idx != -1 {
            remoteHost = remoteAddr[:idx]
            // Ignore port parsing error, default to 0
            _, err := fmt.Sscanf(remoteAddr[idx+1:], "%d", &remotePort)
            if err != nil {
                log.Printf("Error parsing remote port: %v", err)
            }
        }

        // Process the request
        clientPort := 0
        if r.TLS != nil {
            clientPort = 443
        } else {
            clientPort = 80
        }
        tx.ProcessConnection(remoteHost, remotePort, r.Host, clientPort)
        tx.ProcessURI(r.URL.String(), r.Method, r.Proto)
        
        // Process headers
        for name, values := range r.Header {
            for _, value := range values {
                tx.AddRequestHeader(name, value)
            }
        }

        // Process request body if present
        if r.Body != nil {
            tx.ProcessRequestBody()
        }

        // Finalize request processing
        interrupted := tx.ProcessRequestHeaders()
        
        // Check if any rules were triggered
        if interrupted != nil {
            http.Error(w, "Access Denied", http.StatusForbidden)
            return
        }

        // Allow the request
        w.WriteHeader(http.StatusOK)
    })

    log.Printf("Starting Coraza WAF forward auth service on %s", os.Getenv("CORAZA_PROXY_LISTEN"))
    if err := http.ListenAndServe(os.Getenv("CORAZA_PROXY_LISTEN"), nil); err != nil {
        log.Fatal(err)
    }
}
EOF

# Initialize go module and install specific version of Coraza
RUN go mod init coraza-forward-auth && \
    go get github.com/corazawaf/coraza/v3@v3.0.0 && \
    go mod tidy && \
    go build -o coraza-waf

# Final stage
FROM alpine:3.19

# Copy binary and set up directories
COPY --from=builder /app/coraza-waf /app/coraza-waf
RUN mkdir -p /etc/coraza/rules /var/log/coraza && \
    chmod 755 /var/log/coraza

WORKDIR /app

# Expose the default port
EXPOSE 8080

# Set environment variables with defaults
ENV CORAZA_PROXY_LISTEN=":8080" \
    CORAZA_RULES_FILE="/etc/coraza/rules/main.conf"

CMD ["/app/coraza-waf"]
