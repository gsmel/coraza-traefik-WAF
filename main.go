package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/fsnotify/fsnotify"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	requestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "coraza_requests_total",
			Help: "Total number of requests processed by Coraza WAF",
		},
		[]string{"status", "method", "path", "destination", "rule_id", "source_ip", "page_load_id"},
	)

	ruleMatchesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "coraza_rule_matches_total",
			Help: "Total number of rule matches by rule ID",
		},
		[]string{"rule_id", "severity", "method", "path", "destination", "message", "source_ip", "page_load_id"},
	)

	requestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "coraza_request_duration_seconds",
			Help:    "Request duration in seconds",
			Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
		},
		[]string{"status", "destination", "rule_id", "source_ip", "page_load_id"},
	)
)

func generateConfiguration(rulesDir string) string {
	var configLines []string

	configLines = append(configLines, fmt.Sprintf("Include %s", filepath.Join(rulesDir, "crs-setup.conf")))

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

	files, err := filepath.Glob(filepath.Join(rulesDir, "*.conf"))
	if err != nil {
		log.Printf("Error finding rule files: %v", err)
		return ""
	}

	sort.Strings(files)

	for _, file := range files {
		if !strings.HasSuffix(file, "crs-setup.conf") {
			configLines = append(configLines, fmt.Sprintf("Include %s", file))
		}
	}

	return strings.Join(configLines, "\n")
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	rulesDir := "/etc/coraza/rules"

	configStr := generateConfiguration(rulesDir)
	if configStr == "" {
		log.Fatal("Failed to generate configuration")
	}

	log.Printf("Generated configuration:\n%s", configStr)

	config := coraza.NewWAFConfig().WithDirectives(configStr)

	waf, err := coraza.NewWAF(config)
	if err != nil {
		log.Fatal(err)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	err = watcher.Add(rulesDir)
	if err != nil {
		log.Printf("Error watching rules directory: %v", err)
	}

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
					log.Printf("Rule file modified: %s", event.Name)

					newConfigStr := generateConfiguration(rulesDir)
					if newConfigStr == "" {
						log.Printf("Failed to generate new configuration")
						continue
					}

					log.Printf("New configuration:\n%s", newConfigStr)

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

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		path := r.URL.Path
		method := r.Method
		
		// Get the original destination from Traefik headers
		destination := r.Host
		if originalHost := r.Header.Get("X-Forwarded-Host"); originalHost != "" {
			destination = originalHost
		}
		
		source := r.RemoteAddr
		if fwdFor := r.Header.Get("X-Forwarded-For"); fwdFor != "" {
			source = fwdFor
		}

		// Extract page load ID from header, fallback to "none" if not present
		pageLoadID := r.Header.Get("X-Page-Load-ID")
		if pageLoadID == "" {
			pageLoadID = "none"
		}

		tx := waf.NewTransaction()
		defer func() {
			if tx != nil {
				tx.ProcessLogging()
				tx.Close()
				requestDuration.WithLabelValues(
					"allowed",
					destination,
					"0",
					source,
					pageLoadID,
				).Observe(time.Since(start).Seconds())
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

		// Update connection processing to use original host
		log.Printf("Processing connection: %s:%d -> %s:%d", remoteHost, remotePort, destination, clientPort)
		tx.ProcessConnection(remoteHost, remotePort, destination, clientPort)
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
			ruleID := fmt.Sprintf("%d", interrupted.RuleID)
			severity := fmt.Sprintf("%d", interrupted.Status)
			
			log.Printf("[BLOCKED] src=%s dst=%s:%s status=403 rule_id=%s severity=%s",
				source, destination, path, ruleID, severity)

			requestsTotal.WithLabelValues(
				"blocked", 
				method, 
				path,
				destination,
				ruleID,
				source,
				pageLoadID,
			).Inc()

			ruleMatchesTotal.WithLabelValues(
				ruleID,
				severity,
				method,
				path,
				destination,
				fmt.Sprintf("%v", interrupted.Action),
				source,
				pageLoadID,
			).Inc()

			requestDuration.WithLabelValues(
				"blocked",
				destination,
				ruleID,
				source,
				pageLoadID,
			).Observe(time.Since(start).Seconds())

			http.Error(w, "Access Denied", http.StatusForbidden)
			return
		}

		log.Printf("[PASSED] src=%s dst=%s:%s status=200",
			source, destination, path)

		requestsTotal.WithLabelValues(
			"allowed",
			method,
			path,
			destination,
			"0",
			source,
			pageLoadID,
		).Inc()

		requestDuration.WithLabelValues(
			"allowed",
			destination,
			"0",
			source,
			pageLoadID,
		).Observe(time.Since(start).Seconds())
		
		w.WriteHeader(http.StatusOK)
	})

	http.Handle("/metrics", promhttp.Handler())

	addr := os.Getenv("CORAZA_PROXY_LISTEN")
	log.Printf("Starting Coraza WAF forward auth service on %s", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatal(err)
	}
}
