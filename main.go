// Standard Coraza WAF implementation for Traefik forward auth
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/fsnotify/fsnotify"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	waf             coraza.WAF
	lastRulesUpdate time.Time
	requestsTotal   = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "coraza_requests_total",
			Help: "Total number of requests processed by Coraza WAF",
		},
		[]string{"source", "destination", "status"},
	)
	requestsBlocked = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "coraza_requests_blocked",
			Help: "Total number of requests blocked by Coraza WAF",
		},
		[]string{"source", "destination", "rule_id"},
	)
	requestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "coraza_request_duration_seconds",
			Help:    "Duration of requests processed by Coraza WAF",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"source", "destination", "status"},
	)
)

func init() {
	prometheus.MustRegister(requestsTotal)
	prometheus.MustRegister(requestsBlocked)
	prometheus.MustRegister(requestDuration)
}

func generateConfiguration(rulesDir string) string {
	var configLines []string

	// Basic engine configuration
	configLines = append(configLines, "SecRuleEngine On")
	
	// Logging configuration
	configLines = append(configLines, "SecDebugLog /dev/stdout")
	configLines = append(configLines, "SecDebugLogLevel 1")
	configLines = append(configLines, "SecAuditEngine RelevantOnly")
	configLines = append(configLines, "SecAuditLogType Serial")
	configLines = append(configLines, "SecAuditLog /dev/stdout")
	configLines = append(configLines, "SecAuditLogParts ABCFHZ")
	// Removed unsupported regex pattern that was causing the WAF to fail to load rules
	// configLines = append(configLines, "SecAuditLogRelevantStatus \"^(?:5|4(?!04))\"")
	// Using a simpler regex pattern that's supported by Go's regex engine
	configLines = append(configLines, "SecAuditLogRelevantStatus \"^[45]\"")
	
	// Request limits
	configLines = append(configLines, "SecRequestBodyLimit 13107200")          // Default: 13MB
	configLines = append(configLines, "SecRequestBodyInMemoryLimit 131072")    // Default: 128KB
	configLines = append(configLines, "SecResponseBodyLimit 1048576")          // Default: 1MB
	
	// MIME types
	configLines = append(configLines, "SecResponseBodyMimeType application/json")
	configLines = append(configLines, "SecResponseBodyMimeType text/plain")
	configLines = append(configLines, "SecResponseBodyMimeType text/html")
	configLines = append(configLines, "SecResponseBodyMimeType application/javascript")

	// Include all rule files from the directory in a deterministic order
	files, err := filepath.Glob(filepath.Join(rulesDir, "*.conf"))
	if err != nil {
		log.Printf("Error finding rule files: %v", err)
		return ""
	}

	// Also include data files that rules may reference
	dataFiles, err := filepath.Glob(filepath.Join(rulesDir, "*.data"))
	if err != nil {
		log.Printf("Error finding data files: %v", err)
	} else {
		// Data files are just referenced by rules, they don't need to be included in config
		log.Printf("Found %d data files for rules to reference", len(dataFiles))
	}

	sort.Strings(files)
	
	// Add OWASP CRS configuration first (if exists)
	crsSetupFile := filepath.Join(rulesDir, "crs-setup.conf")
	if _, err := os.Stat(crsSetupFile); err == nil {
		configLines = append(configLines, fmt.Sprintf("Include %s", crsSetupFile))
	}
	
	// Include all CoreRuleSet files
	for _, file := range files {
		// Skip the CRS setup file as we've already included it
		if file == crsSetupFile {
			continue
		}
		configLines = append(configLines, fmt.Sprintf("Include %s", file))
	}

	return strings.Join(configLines, "\n")
}

func reloadRules(rulesDir string) {
	log.Printf("Loading WAF rules from %s", rulesDir)
	config := generateConfiguration(rulesDir)
	if config == "" {
		log.Printf("Error loading configuration, no rules to load")
		return
	}

	wafConfig := coraza.NewWAFConfig().
		WithErrorCallback(func(rule types.MatchedRule) {
			// Log errors but don't stop processing
			log.Printf("WAF rule error (non-fatal): Rule ID %d triggered an error", rule.Rule().ID())
		}).
		WithDirectives(config)

	newWaf, err := coraza.NewWAF(wafConfig)
	if err != nil {
		log.Printf("Error loading WAF config: %v", err)
		return
	}

	log.Printf("WAF rules loaded successfully")
	waf = newWaf
	lastRulesUpdate = time.Now()
}

func watchRulesDirectory(rulesDir string) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("Error creating file watcher: %v", err)
		return
	}
	defer watcher.Close()

	log.Printf("Watching rules directory: %s", rulesDir)
	err = watcher.Add(rulesDir)
	if err != nil {
		log.Printf("Error watching rules directory: %v", err)
		return
	}

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Remove) != 0 {
				log.Printf("Rules directory changed, reloading rules")
				time.Sleep(1 * time.Second) // Small debounce
				reloadRules(rulesDir)
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Printf("Watcher error: %v", err)
		}
	}
}

func main() {
	listenAddr := os.Getenv("CORAZA_PROXY_LISTEN")
	if listenAddr == "" {
		listenAddr = ":9080"
	}

	rulesDir := os.Getenv("CORAZA_RULES_DIR")
	if rulesDir == "" {
		rulesDir = "/etc/coraza/rules"
	}

	metricsAddr := os.Getenv("CORAZA_METRICS_LISTEN")
	if metricsAddr == "" {
		metricsAddr = ":9090"
	}

	flag.StringVar(&listenAddr, "listen", listenAddr, "Listen address")
	flag.StringVar(&rulesDir, "rules", rulesDir, "Rules directory")
	flag.StringVar(&metricsAddr, "metrics", metricsAddr, "Metrics listen address")
	flag.Parse()

	// Create metrics server
	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.Handler())
	metricsServer := &http.Server{
		Addr:    metricsAddr,
		Handler: metricsMux,
	}

	// Start metrics server in a separate goroutine
	go func() {
		log.Printf("Starting metrics server on %s", metricsAddr)
		if err := metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Error starting metrics server: %v", err)
		}
	}()

	// Initialize WAF
	reloadRules(rulesDir)
	if waf == nil {
		log.Fatalf("Failed to initialize WAF")
	}

	// Start the rules watcher in a separate goroutine
	go watchRulesDirectory(rulesDir)

	// Create main server
	mainMux := http.NewServeMux()
	mainMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		destination := r.Host
		if originalHost := r.Header.Get("X-Forwarded-Host"); originalHost != "" {
			destination = originalHost
		}
		source := r.RemoteAddr
		if fwdFor := r.Header.Get("X-Forwarded-For"); fwdFor != "" {
			ips := strings.Split(fwdFor, ",")
			source = strings.TrimSpace(ips[0])
		}

		// Special handling for WebSockets and OPTIONS requests
		if r.Method == "OPTIONS" || isWebSocketRequest(r) {
			w.Header().Set("X-Coraza-Status", "BYPASSED")
			w.WriteHeader(http.StatusOK)
			requestsTotal.WithLabelValues(source, destination, "bypassed").Inc()
			return
		}

		// Process request through WAF
		tx := waf.NewTransaction()
		defer tx.ProcessLogging()

		// Add request details to transaction
		remoteHost := source
		remotePort := 0
		if idx := strings.LastIndex(source, ":"); idx != -1 {
			portStr := source[idx+1:]
			remoteHost = source[:idx]
			_, _ = fmt.Sscanf(portStr, "%d", &remotePort)
		}
		serverPort := 80
		if r.Header.Get("X-Forwarded-Proto") == "https" {
			serverPort = 443
		}
		fullURI := r.URL.String()
		if forwardedURI := r.Header.Get("X-Forwarded-Uri"); forwardedURI != "" {
			fullURI = forwardedURI
		}

		// Process connection and URI
		tx.ProcessConnection(remoteHost, remotePort, destination, serverPort)
		tx.ProcessURI(fullURI, r.Method, r.Proto)

		// Process all request headers
		for name, values := range r.Header {
			for _, value := range values {
				tx.AddRequestHeader(name, value)
			}
		}
		tx.AddRequestHeader("Host", destination)

		// Process request headers
		if it := tx.ProcessRequestHeaders(); it != nil {
			requestsBlocked.WithLabelValues(source, destination, strconv.Itoa(it.RuleID)).Inc()
			w.Header().Set("X-Coraza-Status", "BLOCKED")
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// Only process request bodies for specific content types and methods
		if shouldProcessRequestBody(r) {
			if r.Body != nil && r.ContentLength > 0 && r.ContentLength < 1024*1024*10 { // Only process bodies less than 10MB
				bodyBytes, err := io.ReadAll(r.Body)
				if err != nil {
					log.Printf("Error reading request body: %v", err)
					// Continue processing rather than blocking the request
					w.Header().Set("X-Coraza-Status", "PASSED")
					w.WriteHeader(http.StatusOK)
					return
				}
				
				// Restore the body for further processing
				r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
				
				// Process body
				_, _, err = tx.WriteRequestBody(bodyBytes)
				if err != nil {
					log.Printf("Error writing request body: %v", err)
					// Continue processing rather than blocking on error
					w.Header().Set("X-Coraza-Status", "PASSED")
					w.WriteHeader(http.StatusOK)
					return
				}
				
				if it, err := tx.ProcessRequestBody(); err != nil {
					log.Printf("Error processing request body: %v", err)
					// Continue processing rather than blocking on error
					w.Header().Set("X-Coraza-Status", "PASSED")
					w.WriteHeader(http.StatusOK)
					return
				} else if it != nil {
					requestsBlocked.WithLabelValues(source, destination, strconv.Itoa(it.RuleID)).Inc()
					w.Header().Set("X-Coraza-Status", "BLOCKED")
					http.Error(w, "Forbidden", http.StatusForbidden)
					return
				}
			}
		}

		// Request passed WAF checks
		requestsTotal.WithLabelValues(source, destination, "200").Inc()
		requestDuration.WithLabelValues(source, destination, "200").Observe(time.Since(start).Seconds())

		// Forward the request
		w.Header().Set("X-Coraza-Status", "PASSED")
		w.WriteHeader(http.StatusOK)
	})

	mainServer := &http.Server{
		Addr:    listenAddr,
		Handler: mainMux,
	}

	// Start main server
	log.Printf("Starting WAF server on %s", listenAddr)
	if err := mainServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Error starting WAF server: %v", err)
	}
}

// isWebSocketRequest checks if the request is a WebSocket connection attempt
func isWebSocketRequest(r *http.Request) bool {
	conn := strings.ToLower(r.Header.Get("Connection"))
	upgrade := strings.ToLower(r.Header.Get("Upgrade"))
	return strings.Contains(conn, "upgrade") || upgrade != ""
}

// shouldProcessRequestBody determines if the body should be processed
func shouldProcessRequestBody(r *http.Request) bool {
	// Only process certain methods
	if r.Method != "POST" && r.Method != "PUT" && r.Method != "PATCH" {
		return false
	}
	
	// Skip binary content types
	contentType := r.Header.Get("Content-Type")
	if strings.HasPrefix(contentType, "image/") ||
	   strings.HasPrefix(contentType, "video/") ||
	   strings.HasPrefix(contentType, "audio/") ||
	   strings.HasPrefix(contentType, "application/octet-stream") ||
	   strings.HasPrefix(contentType, "application/zip") ||
	   strings.HasPrefix(contentType, "application/pdf") ||
	   strings.HasPrefix(contentType, "application/vnd.") ||
	   strings.Contains(contentType, "multipart/form-data") {
		return false
	}
	
	return true
}
