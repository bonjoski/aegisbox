package proxy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Standard environment variable names for LLM credentials and base URLs
const (
	EnvAnthropicAPIKey    = "ANTHROPIC_API_KEY"
	EnvAnthropicBaseURL   = "ANTHROPIC_BASE_URL"
	EnvOpenAIAPIKey       = "OPENAI_API_KEY"
	EnvOpenAIBaseURL      = "OPENAI_BASE_URL"
	EnvGeminiAPIKey       = "GEMINI_API_KEY"
	EnvGoogleAPIKey       = "GOOGLE_API_KEY"
	EnvGeminiAPIBase      = "GEMINI_API_BASE"
	EnvGoogleGenAIBaseURL = "GOOGLE_GENAI_BASE_URL"
)

// IsLLMCredential returns true if the environment variable is a known LLM secret that should be proxied.
func IsLLMCredential(key string) bool {
	normalized := strings.ToUpper(strings.ReplaceAll(key, "-", "_"))
	switch normalized {
	case EnvAnthropicAPIKey, EnvOpenAIAPIKey, EnvGeminiAPIKey, EnvGoogleAPIKey:
		return true
	default:
		return false
	}
}

// Config specifies settings for the loopback credential proxy.
type Config struct {
	SessionID   string
	HostSecrets map[string]string
	ListenAddr  string // Defaults to "127.0.0.1:0"
}

// CredentialProxy runs a local loopback HTTP server that receives sandbox requests,
// authenticates them using an ephemeral session token, and forwards them upstream
// with real credentials injected.
type CredentialProxy struct {
	sessionID  string
	listener   net.Listener
	server     *http.Server
	proxyToken string
	secrets    map[string]string
	addr       string
	client     *http.Client
	mu         sync.RWMutex
	auditCount int
}

// NewCredentialProxy creates and initializes a new CredentialProxy.
func NewCredentialProxy(cfg Config) (*CredentialProxy, error) {
	randBytes := make([]byte, 16)
	if _, err := rand.Read(randBytes); err != nil {
		return nil, fmt.Errorf("failed to generate proxy session token: %w", err)
	}
	token := "aegis-tok-" + hex.EncodeToString(randBytes)

	listenAddr := cfg.ListenAddr
	if listenAddr == "" {
		listenAddr = "127.0.0.1:0"
	}

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to bind loopback credential proxy: %w", err)
	}

	cleanSecrets := make(map[string]string)
	for k, v := range cfg.HostSecrets {
		if v != "" {
			normalized := strings.ToUpper(strings.ReplaceAll(k, "-", "_"))
			cleanSecrets[normalized] = v
			cleanSecrets[k] = v
		}
	}

	p := &CredentialProxy{
		sessionID:  cfg.SessionID,
		listener:   ln,
		proxyToken: token,
		secrets:    cleanSecrets,
		addr:       ln.Addr().String(),
		client: &http.Client{
			Timeout: 120 * time.Second,
			Transport: &http.Transport{
				Proxy:                 http.ProxyFromEnvironment,
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			},
		},
	}

	p.server = &http.Server{
		Handler:      p,
		ReadTimeout:  120 * time.Second,
		WriteTimeout: 120 * time.Second,
	}

	return p, nil
}

// Start launches the loopback proxy in the background.
func (p *CredentialProxy) Start() {
	go func() {
		_ = p.server.Serve(p.listener)
	}()
}

// Close gracefully shuts down the credential proxy.
func (p *CredentialProxy) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return p.server.Shutdown(ctx)
}

// BaseURL returns the loopback HTTP base URL (e.g. "http://127.0.0.1:54321").
func (p *CredentialProxy) BaseURL() string {
	return "http://" + p.addr
}

// ProxyToken returns the ephemeral authorization token required for sandbox requests.
func (p *CredentialProxy) ProxyToken() string {
	return p.proxyToken
}

// RequestCount returns the total number of proxied requests handled.
func (p *CredentialProxy) RequestCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.auditCount
}

// SandboxEnv returns the synthetic environment variables to inject into the sandbox.
// Real secrets are replaced with the ephemeral proxyToken, and provider base URLs
// are directed to the loopback proxy.
func (p *CredentialProxy) SandboxEnv() map[string]string {
	env := make(map[string]string)
	baseURL := p.BaseURL()

	if _, ok := p.secrets[EnvAnthropicAPIKey]; ok {
		env[EnvAnthropicAPIKey] = p.proxyToken
		env[EnvAnthropicBaseURL] = baseURL + "/anthropic"
	}
	if _, ok := p.secrets[EnvOpenAIAPIKey]; ok {
		env[EnvOpenAIAPIKey] = p.proxyToken
		env[EnvOpenAIBaseURL] = baseURL + "/openai/v1"
	}
	if _, ok := p.secrets[EnvGeminiAPIKey]; ok {
		env[EnvGeminiAPIKey] = p.proxyToken
		env[EnvGeminiAPIBase] = baseURL + "/gemini"
		env[EnvGoogleGenAIBaseURL] = baseURL + "/gemini"
	}
	if _, ok := p.secrets[EnvGoogleAPIKey]; ok {
		env[EnvGoogleAPIKey] = p.proxyToken
		env[EnvGeminiAPIBase] = baseURL + "/gemini"
		env[EnvGoogleGenAIBaseURL] = baseURL + "/gemini"
	}

	env["AEGISBOX_CREDENTIAL_PROXY"] = baseURL
	return env
}

func (p *CredentialProxy) authenticateRequest(r *http.Request) bool {
	// Check x-api-key (Anthropic)
	if val := r.Header.Get("x-api-key"); val == p.proxyToken {
		return true
	}

	// Check Authorization: Bearer <token> (OpenAI)
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		token := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
		if token == p.proxyToken {
			return true
		}
	}

	// Check x-goog-api-key (Google Gemini)
	if val := r.Header.Get("x-goog-api-key"); val == p.proxyToken {
		return true
	}

	// Check ?key=<token> in URL query (Google Gemini / API Gateway)
	if val := r.URL.Query().Get("key"); val == p.proxyToken {
		return true
	}

	return false
}

func (p *CredentialProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Healthcheck or probe endpoint
	if r.URL.Path == "/healthz" || r.URL.Path == "/aegisbox/health" {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","aegisbox_proxy":true}`))
		return
	}

	// 1. Authenticate request using ephemeral proxy token
	if !p.authenticateRequest(r) {
		http.Error(w, `{"error":{"message":"Unauthorized: invalid or missing Aegisbox sandbox proxy token","type":"authentication_error"}}`, http.StatusUnauthorized)
		return
	}

	p.mu.Lock()
	p.auditCount++
	p.mu.Unlock()

	// 2. Route request to appropriate upstream provider
	var (
		targetHost string
		targetPath string
		authHeader string
		realSecret string
	)

	path := r.URL.Path

	switch {
	case strings.HasPrefix(path, "/anthropic"):
		targetHost = "api.anthropic.com"
		targetPath = strings.TrimPrefix(path, "/anthropic")
		authHeader = "x-api-key"
		realSecret = p.secrets[EnvAnthropicAPIKey]

	case strings.HasPrefix(path, "/openai"):
		targetHost = "api.openai.com"
		targetPath = strings.TrimPrefix(path, "/openai")
		authHeader = "Authorization"
		realSecret = p.secrets[EnvOpenAIAPIKey]

	case strings.HasPrefix(path, "/gemini"):
		targetHost = "generativelanguage.googleapis.com"
		targetPath = strings.TrimPrefix(path, "/gemini")
		authHeader = "x-goog-api-key"
		realSecret = p.secrets[EnvGeminiAPIKey]
		if realSecret == "" {
			realSecret = p.secrets[EnvGoogleAPIKey]
		}

	default:
		// Fallback heuristics for direct root baseURL usage
		switch {
		case strings.HasPrefix(path, "/v1/messages") || strings.HasPrefix(path, "/v1/complete"):
			targetHost = "api.anthropic.com"
			targetPath = path
			authHeader = "x-api-key"
			realSecret = p.secrets[EnvAnthropicAPIKey]

		case strings.HasPrefix(path, "/v1/chat") || strings.HasPrefix(path, "/v1/models") || strings.HasPrefix(path, "/v1/embeddings"):
			targetHost = "api.openai.com"
			targetPath = path
			authHeader = "Authorization"
			realSecret = p.secrets[EnvOpenAIAPIKey]

		case strings.HasPrefix(path, "/v1beta") || strings.HasPrefix(path, "/v1alpha"):
			targetHost = "generativelanguage.googleapis.com"
			targetPath = path
			authHeader = "x-goog-api-key"
			realSecret = p.secrets[EnvGeminiAPIKey]
			if realSecret == "" {
				realSecret = p.secrets[EnvGoogleAPIKey]
			}

		default:
			// If only one provider is configured, route root path to that provider
			if p.secrets[EnvAnthropicAPIKey] != "" && len(p.secrets) == 1 {
				targetHost = "api.anthropic.com"
				targetPath = path
				authHeader = "x-api-key"
				realSecret = p.secrets[EnvAnthropicAPIKey]
			} else if p.secrets[EnvOpenAIAPIKey] != "" && len(p.secrets) == 1 {
				targetHost = "api.openai.com"
				targetPath = path
				authHeader = "Authorization"
				realSecret = p.secrets[EnvOpenAIAPIKey]
			} else if (p.secrets[EnvGeminiAPIKey] != "" || p.secrets[EnvGoogleAPIKey] != "") && len(p.secrets) == 1 {
				targetHost = "generativelanguage.googleapis.com"
				targetPath = path
				authHeader = "x-goog-api-key"
				realSecret = p.secrets[EnvGeminiAPIKey]
				if realSecret == "" {
					realSecret = p.secrets[EnvGoogleAPIKey]
				}
			} else {
				http.Error(w, `{"error":{"message":"Bad Request: unable to route request to LLM upstream provider","type":"invalid_request_error"}}`, http.StatusBadRequest)
				return
			}
		}
	}

	if targetPath == "" {
		targetPath = "/"
	}
	if realSecret == "" {
		http.Error(w, `{"error":{"message":"Proxy Error: real secret key not configured on host for this provider","type":"proxy_error"}}`, http.StatusBadGateway)
		return
	}

	// 3. Build upstream request
	upstreamURL := url.URL{
		Scheme:   "https",
		Host:     targetHost,
		Path:     targetPath,
		RawQuery: r.URL.RawQuery,
	}

	// Clean up query if dummy token was passed in query param
	if upstreamURL.RawQuery != "" {
		q := upstreamURL.Query()
		if q.Get("key") == p.proxyToken {
			if authHeader == "x-goog-api-key" {
				q.Set("key", realSecret)
			} else {
				q.Del("key")
			}
			upstreamURL.RawQuery = q.Encode()
		}
	}

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL.String(), r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Forward client headers, stripping incoming authentication
	for k, vv := range r.Header {
		switch strings.ToLower(k) {
		case "authorization", "x-api-key", "x-goog-api-key", "host", "content-length":
			continue
		default:
			for _, v := range vv {
				outReq.Header.Add(k, v)
			}
		}
	}

	// Inject real credential
	switch authHeader {
	case "Authorization":
		outReq.Header.Set("Authorization", "Bearer "+realSecret)
	case "x-api-key":
		outReq.Header.Set("x-api-key", realSecret)
	case "x-goog-api-key":
		outReq.Header.Set("x-goog-api-key", realSecret)
	}

	outReq.Host = targetHost

	// 4. Execute upstream request
	resp, err := p.client.Do(outReq)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":{"message":"Upstream provider communication error: %v","type":"upstream_error"}}`, err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// 5. Forward response headers, stripping hop-by-hop headers
	for k, vv := range resp.Header {
		switch strings.ToLower(k) {
		case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers", "transfer-encoding", "upgrade", "content-length":
			continue
		default:
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
	}
	w.WriteHeader(resp.StatusCode)


	// 6. Stream response body back to client with real-time flushing
	flusher, isFlusher := w.(http.Flusher)
	buf := make([]byte, 32*1024)
	for {
		n, rErr := resp.Body.Read(buf)
		if n > 0 {
			if _, wErr := w.Write(buf[:n]); wErr != nil {
				break
			}
			if isFlusher {
				flusher.Flush()
			}
		}
		if rErr != nil {
			break
		}
	}
}
