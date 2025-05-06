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
        waf              coraza.WAF
        lastRulesUpdate  time.Time
        requestsTotal = prometheus.NewCounterVec(
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
        // Add a new gauge to track total blocked vs allowed requests
        requestStatus = prometheus.NewGaugeVec(
                prometheus.GaugeOpts{
                        Name: "coraza_request_status",
                        Help: "Current status of requests (1=blocked, 0=allowed)",
					},
					[]string{"source", "destination", "action"},
			)
	)
	
	func init() {
			prometheus.MustRegister(requestsTotal)
			prometheus.MustRegister(requestsBlocked)
			prometheus.MustRegister(requestDuration)
			prometheus.MustRegister(requestStatus) // Register the new metric
	}
	
	func generateConfiguration(rulesDir string) string {
			var configLines []string
	
			// Basic configuration
			configLines = append(configLines,
					"SecRuleEngine On",
					"SecDebugLog /dev/stdout",
					"SecDebugLogLevel 5",
					"SecAuditEngine On",
					"SecAuditLogType Serial",
					"SecAuditLog /dev/stdout",
					"SecAuditLogParts ABCDEFHIJKZ",
					`SecAuditLogRelevantStatus ".*"`,
	
					// Set paranoia level to 2 (higher security) - use custom ID range to avoid conflicts
					`SecAction "id:800000,phase:1,nolog,pass,t:none,setvar:tx.paranoia_level=2"`,
	
					// Lower the anomaly thresholds to make blocking more aggressive
					`SecAction "id:800110,phase:1,nolog,pass,t:none,setvar:tx.inbound_anomaly_score_threshold=3"`,
					`SecAction "id:800111,phase:1,nolog,pass,t:none,setvar:tx.outbound_anomaly_score_threshold=3"`,
	
					// Enable request body inspection
					`SecAction "id:800200,phase:1,nolog,pass,t:none,setvar:tx.enforce_bodyproc_urlencoded=1"`,
	
					// Add detection mode settings - use custom ID range (800xxx instead of 900xxx)
					`SecAction "id:800990,phase:1,nolog,pass,t:none,setvar:tx.blocking_paranoia_level=2"`,
					`SecAction "id:800991,phase:1,nolog,pass,t:none,setvar:tx.detection_paranoia_level=2"`,
			)
	
			// Include all rule files
			files, err := filepath.Glob(filepath.Join(rulesDir, "*.conf"))
			if err != nil {
					log.Printf("Error finding rule files: %v", err)
					return ""
			}

			sort.Strings(files)
	
			 // First add only basic-rules.conf to ensure we have at least one functioning set of rules
			basicRulesFile := filepath.Join(rulesDir, "basic-rules.conf")
			foundBasicRules := false
			for _, file := range files {
					if file == basicRulesFile {
							foundBasicRules = true
							configLines = append(configLines, fmt.Sprintf("Include %s", basicRulesFile))
							break
					}
			}
	
			// If basic rules weren't found, create them on the fly
			if !foundBasicRules {
					log.Printf("No basic-rules.conf found, creating fallback rules")
					basicRules := []string{
							"# Fallback rules automatically generated",
							"SecRule REQUEST_URI \"@contains /admin\" \"id:1000,phase:1,deny,status:403,msg:'Admin access blocked'\"",
							"SecRule ARGS \"@contains SELECT FROM\" \"id:1001,phase:2,deny,status:403,msg:'SQL Injection attempt detected'\"",
							"SecRule ARGS \"@contains <script>\" \"id:1002,phase:2,deny,status:403,msg:'XSS attempt detected'\"",
					}
					basicRulesContent := strings.Join(basicRules, "\n")
					basicRulesPath := filepath.Join(rulesDir, "basic-rules.conf")
					if err := os.WriteFile(basicRulesPath, []byte(basicRulesContent), 0644); err != nil {
							log.Printf("Error writing fallback rules: %v", err)
					} else {
							configLines = append(configLines, fmt.Sprintf("Include %s", basicRulesPath))
					}
			}
	
			// Special handling for CRS setup file - include it with try
			crsSetupFile := filepath.Join(rulesDir, "crs-setup.conf")
			for _, file := range files {
					if file == crsSetupFile {
							configLines = append(configLines, fmt.Sprintf("# Try to include CRS setup\nInclude %s", crsSetupFile))
							break
					}
			}
	
			// Try to include other rule files, but use a safe approach
			safeToInclude := []string{
					"REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf",
					"REQUEST-901-INITIALIZATION.conf",
					"REQUEST-905-COMMON-EXCEPTIONS.conf",
					"REQUEST-912-DOS-PROTECTION.conf", 
					"REQUEST-920-PROTOCOL-ENFORCEMENT.conf",
					"REQUEST-921-PROTOCOL-ATTACK.conf",
					"REQUEST-930-APPLICATION-ATTACK-LFI.conf",
					"REQUEST-932-APPLICATION-ATTACK-RCE.conf",
					"REQUEST-941-APPLICATION-ATTACK-XSS.conf",
					"REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
					"REQUEST-949-BLOCKING-EVALUATION.conf",
			}
	
			for _, safeFile := range safeToInclude {
					fullPath := filepath.Join(rulesDir, safeFile)
					for _, file := range files {
							if file == fullPath {
									configLines = append(configLines, fmt.Sprintf("Include %s", file))
									break
							}
					}
			}
	
			// Add an explicit enforcement rule at the end - use custom ID in 800xxx range to avoid conflicts
			configLines = append(configLines, 
					`SecAction "id:800005,phase:1,pass,nolog,ctl:ruleEngine=On"`,
					`SecRule TX:BLOCKING_INBOUND_ANOMALY_SCORE "@ge 3" "id:800999,phase:2,deny,status:403,log,msg:'Inbound Anomaly Score Exceeded'"`,
			)
	
			return strings.Join(configLines, "\n")
	}
	
	func generateFallbackConfiguration() string {
		return `
# Basic WAF configuration with only essential rules
SecRuleEngine On
SecDebugLog /dev/stdout
SecDebugLogLevel 3
SecAuditEngine On
SecAuditLog /dev/stdout

# Basic protection rules
SecRule REQUEST_URI "@contains /admin" "id:1000,phase:1,deny,status:403,log,msg:'Admin access blocked'"
SecRule ARGS "@contains SELECT FROM" "id:1001,phase:2,deny,status:403,log,msg:'SQL Injection attempt detected'"
SecRule ARGS "@contains <script>" "id:1002,phase:2,deny,status:403,log,msg:'XSS attempt detected'"
SecRule REQUEST_URI "@contains ../etc/passwd" "id:1003,phase:1,deny,status:403,log,msg:'Path traversal attempt'"
SecRule REQUEST_URI "@contains cmd=" "id:1004,phase:1,deny,status:403,log,msg:'Command injection attempt'"
SecRule ARGS_NAMES "@contains passwd" "id:1005,phase:2,deny,status:403,log,msg:'Suspicious parameter name'"
SecRule REQUEST_HEADERS:User-Agent "@contains sqlmap" "id:1006,phase:1,deny,status:403,log,msg:'Known malicious user agent'"
`
	}
	
	func reloadRules(rulesDir string) {
		log.Printf("Loading WAF rules from %s", rulesDir)
		config := generateConfiguration(rulesDir)
		if config == "" {
			log.Printf("Error loading configuration, using existing configuration")
			return
		}
	
		log.Printf("Generated configuration:\n%s", config)
		wafConfig := coraza.NewWAFConfig().
			WithErrorCallback(func(rule types.MatchedRule) {
				// Log errors but don't stop processing
				log.Printf("WAF rule error (non-fatal): Rule ID %d triggered an error", rule.Rule().ID())
			}).
			WithDirectives(config)
	
		newWaf, err := coraza.NewWAF(wafConfig)
		if err != nil {
			log.Printf("Error loading WAF config from string: %v", err)
			// Try fallback to basic rules
			fallbackConfig := generateFallbackConfiguration()
			log.Printf("Trying fallback configuration")
			newWaf, err = coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(fallbackConfig))
			if err != nil {
				log.Printf("Failed to load fallback WAF configuration: %v", err)
				return
			}
			log.Printf("Loaded fallback WAF configuration")
		} else {
			log.Printf("WAF rules loaded successfully")
		}
	
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
									log.Printf("Rules directory changed, reloading rules in 2 seconds")
									time.Sleep(2 * time.Second) // Debounce
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
	
	func handleInterruption(interrupted *types.Interruption, w http.ResponseWriter, r *http.Request, source, destination, path, method, pageLoadID string, start time.Time) {
			statusCode := interrupted.Status
			if statusCode == 0 {
					statusCode = 403
			}
	
			// Add WAF header
			w.Header().Set("X-Coraza-Status", "BLOCKED")
	
			// Log the blocked request
			log.Printf("Blocked request from %s to %s: %s %s, rule: %d, msg: %s",
					source, destination, method, path, interrupted.RuleID, interrupted.Action)
	
			// Metrics - convert RuleID from int to string for the label
			ruleIDStr := strconv.Itoa(interrupted.RuleID)
			requestsBlocked.WithLabelValues(source, destination, ruleIDStr).Inc()
			requestsTotal.WithLabelValues(source, destination, "blocked").Inc()
			requestDuration.WithLabelValues(source, destination, "blocked").Observe(time.Since(start).Seconds())
			// Add explicit blocked status metric for Grafana
			requestStatus.WithLabelValues(source, destination, "blocked").Set(1)
	
			http.Error(w, "Forbidden", statusCode)
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
	
			reloadRules(rulesDir)
			if waf == nil {
					log.Fatalf("Failed to initialize WAF")
			}
	
			// Start the rules watcher in a separate goroutine
			go watchRulesDirectory(rulesDir)
	
			// Start metrics server
			go func() {
					http.Handle("/metrics", promhttp.Handler())
					log.Printf("Starting metrics server on %s", metricsAddr)
					if err := http.ListenAndServe(metricsAddr, nil); err != nil {
							log.Printf("Error starting metrics server: %v", err)
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
						// Use the first IP in the X-Forwarded-For chain
						ips := strings.Split(fwdFor, ",")
						source = strings.TrimSpace(ips[0])
				}

				// Get the full URL including query string
				fullURI := r.URL.String()
				if forwardedURI := r.Header.Get("X-Forwarded-Uri"); forwardedURI != "" {
						fullURI = forwardedURI
				}

				// Check if this appears to be a web browser request based on headers
				userAgent := r.Header.Get("User-Agent")
				isBrowserRequest := strings.Contains(strings.ToLower(userAgent), "mozilla") ||
						strings.Contains(strings.ToLower(userAgent), "chrome") ||
						strings.Contains(strings.ToLower(userAgent), "safari") ||
						strings.Contains(strings.ToLower(userAgent), "edge") ||
						strings.Contains(strings.ToLower(userAgent), "firefox")

				// Log all incoming requests for debugging
				log.Printf("WAF AUTH REQUEST: %s %s from %s to %s (Browser: %t)", method, fullURI, source, destination, isBrowserRequest)

				// Enhanced pattern detection for attack signatures
				suspicious := false
				suspiciousPatterns := []string{
						"cmd=", "exec=", "system(", "shell_exec", "/etc/passwd",
						"SELECT", "UNION", "DROP", "INSERT", "DELETE", "UPDATE", "1=1", "OR 1=1",
						"<script>", "javascript:", "onerror=", "onload=", "eval(", "alert(", 
						"../", "..\\", "file:", "data:", "base64",
				}

				// Check both the URL and any query parameters
				urlToCheck := strings.ToLower(fullURI)
				for _, pattern := range suspiciousPatterns {
						if strings.Contains(urlToCheck, strings.ToLower(pattern)) {
								suspicious = true
								log.Printf("DETECTED ATTACK PATTERN: %s in URL: %s", pattern, fullURI)
								break
						}
				}
            // Block suspicious requests unless they're from a browser
            if suspicious && !isBrowserRequest {
				log.Printf("BLOCKED: Attack pattern in URL: %s", fullURI)
				w.Header().Set("X-Coraza-Status", "BLOCKED")

				// Add metrics for suspicious pattern blocks
				requestsBlocked.WithLabelValues(source, destination, "suspicious-pattern").Inc()
				requestsTotal.WithLabelValues(source, destination, "blocked").Inc()
				requestDuration.WithLabelValues(source, destination, "blocked").Observe(time.Since(start).Seconds())
				requestStatus.WithLabelValues(source, destination, "blocked").Set(1)

				http.Error(w, "Forbidden - Attack Detected", http.StatusForbidden)
				return
		}

		 // If it's a browser request that looks suspicious, log it but allow through
		// to avoid false positives on legitimate browser navigation
		if suspicious && isBrowserRequest {
				log.Printf("SUSPICIOUS BUT ALLOWED (browser): %s", fullURI)
		}

		// Extract page load ID from header, fallback to "none" if not present
		pageLoadID := r.Header.Get("X-Page-Load-ID")
		if pageLoadID == "" {
				pageLoadID = "none"
		}

		log.Printf("Received request: %s %s from %s", method, path, source)

		tx := waf.NewTransaction()
		defer func() {
				if tx != nil {
						tx.ProcessLogging()
						tx.Close()
				}
		}()

		// Read request body
		var bodyBytes []byte
		if r.Body != nil {
				var err error
				bodyBytes, err = io.ReadAll(r.Body)
				if err != nil {
						log.Printf("Error reading body: %v", err)
						http.Error(w, "Error reading request body", http.StatusBadRequest)
						return
				}
				 // Create a new ReadCloser from the body bytes to allow Traefik to read it again
				r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}

		// Extract connection details
		remoteHost := source
		remotePort := 0
		if idx := strings.LastIndex(source, ":"); idx != -1 {
				portStr := source[idx+1:]
				remoteHost = source[:idx]
				_, err := fmt.Sscanf(portStr, "%d", &remotePort)
				if err != nil {
						log.Printf("Error parsing port from %s: %v", source, err)
				}
		}

		serverPort := 80
		if r.Header.Get("X-Forwarded-Proto") == "https" {
				serverPort = 443
		}

		// Process the full transaction
		tx.ProcessConnection(remoteHost, remotePort, destination, serverPort)
		tx.ProcessURI(fullURI, method, r.Proto)

		// Process all request headers
		for name, values := range r.Header {
				for _, value := range values {
						tx.AddRequestHeader(name, value)
				}
		}

		// Add any missing headers that Traefik might expect
		tx.AddRequestHeader("Host", destination)

		if interrupted := tx.ProcessRequestHeaders(); interrupted != nil {
				// For browser requests with potential false positives, log but allow
				if isBrowserRequest && (interrupted.RuleID >= 942000 && interrupted.RuleID <= 942999) {
						log.Printf("BROWSER FP PREVENTED: Rule %d might be a false positive for %s", interrupted.RuleID, fullURI)
				} else {
						w.Header().Set("X-Coraza-Status", "BLOCKED")
						log.Printf("Blocked request from %s to %s: %s %s, rule: %d, msg: %s",
								source, destination, method, path, interrupted.RuleID, interrupted.Action)

						ruleIDStr := strconv.Itoa(interrupted.RuleID)
						requestsBlocked.WithLabelValues(source, destination, ruleIDStr).Inc()
						requestsTotal.WithLabelValues(source, destination, "blocked").Inc()
						requestDuration.WithLabelValues(source, destination, "blocked").Observe(time.Since(start).Seconds())

						statusCode := interrupted.Status
						if statusCode == 0 {
								statusCode = 403
						}
						http.Error(w, "Forbidden by WAF", statusCode)
						return
				}
		}

            // Process request body if present
            if len(bodyBytes) > 0 {
				log.Printf("Processing body: %d bytes", len(bodyBytes))
				if n, _, err := tx.WriteRequestBody(bodyBytes); err != nil {
						log.Printf("Error writing request body: %v", err)
						http.Error(w, "Error processing request", http.StatusInternalServerError)
						return
				} else {
						log.Printf("Wrote %d bytes to request body", n)
				}

				interrupted, err := tx.ProcessRequestBody()
				if err != nil {
						log.Printf("Error processing request body: %v", err)
						http.Error(w, "Error processing request", http.StatusInternalServerError)
						return
				}
				if interrupted != nil {
						w.Header().Set("X-Coraza-Status", "BLOCKED")
						log.Printf("Blocked request from %s to %s: %s %s, rule: %d, msg: %s",
								source, destination, method, path, interrupted.RuleID, interrupted.Action)

						ruleIDStr := strconv.Itoa(interrupted.RuleID)
						requestsBlocked.WithLabelValues(source, destination, ruleIDStr).Inc()
						requestsTotal.WithLabelValues(source, destination, "blocked").Inc()
						requestDuration.WithLabelValues(source, destination, "blocked").Observe(time.Since(start).Seconds())

						statusCode := interrupted.Status
						if statusCode == 0 {
								statusCode = 403
						}
						http.Error(w, "Forbidden by WAF Rules", statusCode)
						return
				}
		}

		// Request passed all checks, allow it
		log.Printf("ALLOWED request: %s %s from %s to %s", method, fullURI, source, destination)
		w.Header().Set("X-Coraza-Status", "PASSED")

		// Add headers to ensure browser content loads properly
		w.Header().Set("Content-Type", "text/plain")

		// Update metrics
		elapsed := time.Since(start).Seconds()
		requestsTotal.WithLabelValues(source, destination, "passed").Inc()
		requestDuration.WithLabelValues(source, destination, "passed").Observe(elapsed)
		requestStatus.WithLabelValues(source, destination, "allowed").Set(1) // Add explicit allowed status

		log.Printf("Allowed request from %s to %s: %s %s in %.3fs",
		source, destination, method, path, elapsed)

		// Return 200 OK to signal Traefik that the request should be forwarded
		w.WriteHeader(http.StatusOK)
})

log.Printf("Starting WAF forward auth server on %s", listenAddr)
if err := http.ListenAndServe(listenAddr, nil); err != nil {
		log.Fatalf("Error starting server: %v", err)
}
}
