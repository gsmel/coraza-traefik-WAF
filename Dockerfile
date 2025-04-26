# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /app
RUN apk add --no-cache git make

# Create a simple forward auth WAF service
COPY <<'EOF' /app/main.go
package main

import (
    "fmt"
    "log"
    "net/http"
    "os"
    "strings"
    "io"
    "bytes"
    "path/filepath"
    "sort"
    "github.com/corazawaf/coraza/v3"
    "github.com/fsnotify/fsnotify"
)

func generateConfiguration(rulesDir string) string {
    var configLines []string
    
    // First include the CRS setup file
    configLines = append(configLines, fmt.Sprintf("Include %s", filepath.Join(rulesDir, "crs-setup.conf")))
    
    // Add base configuration that will override CRS defaults
    configLines = append(configLines,
        "SecRuleEngine On",
        "SecDebugLog /dev/stdout",
        "SecDebugLogLevel 5",
        "SecAuditEngine On",
        "SecAuditLogType Serial",
        "SecAuditLog /dev/stdout",
        "SecAuditLogParts ABCDEFHIJKZ",
        `SecAuditLogRelevantStatus ".*"`,
    )

    // Then include all other .conf files in sorted order
    files, err := filepath.Glob(filepath.Join(rulesDir, "*.conf"))
    if err != nil {
        log.Printf("Error finding rule files: %v", err)
        return ""
    }

    // Sort files for consistent order
    sort.Strings(files)

    // Add Include directives, skipping crs-setup.conf as it's already included
    for _, file := range files {
        if !strings.HasSuffix(file, "crs-setup.conf") {
            configLines = append(configLines, fmt.Sprintf("Include %s", file))
        }
    }

    // Join with newlines
    return strings.Join(configLines, "\n")
}

func main() {
    log.SetFlags(log.LstdFlags | log.Lmicroseconds)
    
    rulesDir := "/etc/coraza/rules"
    
    // Generate initial configuration
    configStr := generateConfiguration(rulesDir)
    if configStr == "" {
        log.Fatal("Failed to generate configuration")
    }
    
    // Debug log the configuration
    log.Printf("Generated configuration:\n%s", configStr)
    
    // Initialize WAF with configuration
    config := coraza.NewWAFConfig().WithDirectives(configStr)
    
    waf, err := coraza.NewWAF(config)
    if err != nil {
        log.Fatal(err)
    }

    // Set up file watcher
    watcher, err := fsnotify.NewWatcher()
    if err != nil {
        log.Fatal(err)
    }
    defer watcher.Close()

    // Watch rules directory
    err = watcher.Add(rulesDir)
    if err != nil {
        log.Printf("Error watching rules directory: %v", err)
    }

    // Handle rule file changes
    go func() {
        for {
            select {
            case event, ok := <-watcher.Events:
                if !ok {
                    return
                }
                if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
                    log.Printf("Rule file modified: %s", event.Name)
                    
                    // Generate new configuration
                    newConfigStr := generateConfiguration(rulesDir)
                    if newConfigStr == "" {
                        log.Printf("Failed to generate new configuration")
                        continue
                    }
                    
                    // Debug log the new configuration
                    log.Printf("New configuration:\n%s", newConfigStr)
                    
                    // Create new WAF instance
                    newWaf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(newConfigStr))
                    if err != nil {
                        log.Printf("Error reloading rules: %v", err)
                        continue
                    }
                    waf = newWaf
                    log.Printf("Rules reloaded successfully")
                }
            case err, ok := <-watcher.Errors:
                if !ok {
                    return
                }
                log.Printf("Watcher error: %v", err)
            }
        }
    }()

    // Forward auth handler
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        log.Printf("Received request: %s %s from %s", r.Method, r.URL.String(), r.RemoteAddr)
        
        tx := waf.NewTransaction()
        defer func() {
            if tx != nil {
                log.Printf("Processing logging for transaction")
                tx.ProcessLogging()
                tx.Close()
            }
        }()

        var bodyBytes []byte
        if r.Body != nil {
            bodyBytes, err = io.ReadAll(r.Body)
            if err != nil {
                log.Printf("Error reading body: %v", err)
                http.Error(w, "Error reading request body", http.StatusBadRequest)
                return
            }
            r.Body.Close()
            r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
        }
        
        remoteAddr := r.RemoteAddr
        remoteHost := remoteAddr
        remotePort := 0
        if idx := strings.LastIndex(remoteAddr, ":"); idx != -1 {
            remoteHost = remoteAddr[:idx]
            _, err := fmt.Sscanf(remoteAddr[idx+1:], "%d", &remotePort)
            if err != nil {
                log.Printf("Error parsing remote port: %v", err)
            }
        }

        clientPort := 0
        if r.TLS != nil {
            clientPort = 443
        } else {
            clientPort = 80
        }

        log.Printf("Processing connection: %s:%d -> %s:%d", remoteHost, remotePort, r.Host, clientPort)
        tx.ProcessConnection(remoteHost, remotePort, r.Host, clientPort)
        tx.ProcessURI(r.URL.String(), r.Method, r.Proto)
        
        for name, values := range r.Header {
            for _, value := range values {
                log.Printf("Processing header: %s: %s", name, value)
                tx.AddRequestHeader(name, value)
            }
        }

        if len(bodyBytes) > 0 {
            log.Printf("Processing request body of length: %d", len(bodyBytes))
            if _, err := tx.ProcessRequestBody(); err != nil {
                log.Printf("Error processing request body: %v", err)
            }
        }

        interrupted := tx.ProcessRequestHeaders()
        
        if interrupted != nil {
            log.Printf("Request blocked: %v", interrupted)
            http.Error(w, "Access Denied", http.StatusForbidden)
            return
        }

        log.Printf("Request allowed")
        w.WriteHeader(http.StatusOK)
    })

    addr := os.Getenv("CORAZA_PROXY_LISTEN")
    log.Printf("Starting Coraza WAF forward auth service on %s", addr)
    if err := http.ListenAndServe(addr, nil); err != nil {
        log.Fatal(err)
    }
}
EOF

# Initialize go module and install dependencies
RUN go mod init coraza-forward-auth && \
    go get github.com/corazawaf/coraza/v3@v3.0.0 && \
    go get github.com/fsnotify/fsnotify && \
    go mod tidy && \
    go build -o coraza-waf

# Final stage
FROM alpine:3.19

# Install git for CRS updates
RUN apk add --no-cache git

# Copy binary and set up directories
COPY --from=builder /app/coraza-waf /app/coraza-waf
COPY scripts/update-crs.sh /app/update-crs.sh
RUN mkdir -p /etc/coraza/rules && \
    chmod +x /app/update-crs.sh

WORKDIR /app

EXPOSE 8080

ENV CORAZA_PROXY_LISTEN=":8080"

# Initialize CRS rules and start WAF
CMD ["/bin/sh", "-c", "/app/update-crs.sh && /app/coraza-waf"]