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

// Standard environment variable names for common LLM credentials
const (
	EnvAnthropicAPIKey    = "ANTHROPIC_API_KEY"
	EnvAnthropicBaseURL   = "ANTHROPIC_BASE_URL"
	EnvOpenAIAPIKey       = "OPENAI_API_KEY"
	EnvOpenAIBaseURL      = "OPENAI_BASE_URL"
	EnvGeminiAPIKey       = "GEMINI_API_KEY"
	EnvGoogleAPIKey       = "GOOGLE_API_KEY"
	EnvGeminiAPIBase      = "GEMINI_API_BASE"
	EnvGoogleGenAIBaseURL = "GOOGLE_GENAI_BASE_URL"
	EnvMistralAPIKey      = "MISTRAL_API_KEY"
	EnvMistralBaseURL     = "MISTRAL_BASE_URL"
	EnvGroqAPIKey         = "GROQ_API_KEY"
	EnvGroqBaseURL        = "GROQ_BASE_URL"
	EnvDeepSeekAPIKey     = "DEEPSEEK_API_KEY"
	EnvDeepSeekBaseURL    = "DEEPSEEK_BASE_URL"
	EnvOpenRouterAPIKey   = "OPENROUTER_API_KEY"
	EnvOpenRouterBaseURL  = "OPENROUTER_BASE_URL"
	EnvTogetherAPIKey     = "TOGETHER_API_KEY"
	EnvTogetherBaseURL    = "TOGETHER_BASE_URL"
	EnvPerplexityAPIKey   = "PERPLEXITY_API_KEY"
	EnvPerplexityBaseURL  = "PERPLEXITY_BASE_URL"
	EnvCohereAPIKey       = "COHERE_API_KEY"
	EnvCohereBaseURL      = "COHERE_BASE_URL"
	EnvHFToken            = "HF_TOKEN"
	EnvHFBaseURL          = "HF_BASE_URL"
)

// AuthStyle defines how an upstream provider expects its credentials.
type AuthStyle string

const (
	AuthStyleBearer   AuthStyle = "bearer"    // Authorization: Bearer <key>
	AuthStyleHeader   AuthStyle = "header"    // e.g. x-api-key: <key>
	AuthStyleQueryKey AuthStyle = "query_key" // e.g. ?key=<key> and/or x-goog-api-key: <key>
)

// ProviderSpec defines how requests for a specific AI model provider or custom route are proxied.
type ProviderSpec struct {
	ID            string    `json:"id"`
	EnvKeys       []string  `json:"env_keys"`
	BaseURLEnvs   []string  `json:"base_url_envs"`
	DefaultHost   string    `json:"default_host"`
	DefaultScheme string    `json:"default_scheme"` // "https" or "http"
	BasePath      string    `json:"base_path"`      // upstream subpath, e.g. "/v1"
	PathPrefix    string    `json:"path_prefix"`    // proxy path prefix, e.g. "/anthropic" or "/route/custom"
	AuthStyle     AuthStyle `json:"auth_style"`
	AuthHeader    string    `json:"auth_header"`
}

// BuiltinProviders contains standard out-of-the-box configurations for major LLM providers.
var BuiltinProviders = []*ProviderSpec{
	{
		ID:            "anthropic",
		EnvKeys:       []string{EnvAnthropicAPIKey, "ANTHROPIC-API-KEY"},
		BaseURLEnvs:   []string{EnvAnthropicBaseURL},
		DefaultHost:   "api.anthropic.com",
		DefaultScheme: "https",
		PathPrefix:    "/anthropic",
		AuthStyle:     AuthStyleHeader,
		AuthHeader:    "x-api-key",
	},
	{
		ID:            "openai",
		EnvKeys:       []string{EnvOpenAIAPIKey, "OPENAI-API-KEY"},
		BaseURLEnvs:   []string{EnvOpenAIBaseURL},
		DefaultHost:   "api.openai.com",
		DefaultScheme: "https",
		BasePath:      "/v1",
		PathPrefix:    "/openai/v1",
		AuthStyle:     AuthStyleBearer,
		AuthHeader:    "Authorization",
	},
	{
		ID:            "openai-root",
		EnvKeys:       []string{EnvOpenAIAPIKey, "OPENAI-API-KEY"},
		BaseURLEnvs:   []string{},
		DefaultHost:   "api.openai.com",
		DefaultScheme: "https",
		PathPrefix:    "/openai",
		AuthStyle:     AuthStyleBearer,
		AuthHeader:    "Authorization",
	},
	{
		ID:            "gemini",
		EnvKeys:       []string{EnvGeminiAPIKey, "GEMINI-API-KEY", EnvGoogleAPIKey, "GOOGLE-API-KEY"},
		BaseURLEnvs:   []string{EnvGeminiAPIBase, EnvGoogleGenAIBaseURL},
		DefaultHost:   "generativelanguage.googleapis.com",
		DefaultScheme: "https",
		PathPrefix:    "/gemini",
		AuthStyle:     AuthStyleQueryKey,
		AuthHeader:    "x-goog-api-key",
	},
	{
		ID:            "mistral",
		EnvKeys:       []string{EnvMistralAPIKey, "MISTRAL-API-KEY"},
		BaseURLEnvs:   []string{EnvMistralBaseURL},
		DefaultHost:   "api.mistral.ai",
		DefaultScheme: "https",
		PathPrefix:    "/mistral",
		AuthStyle:     AuthStyleBearer,
		AuthHeader:    "Authorization",
	},
	{
		ID:            "groq",
		EnvKeys:       []string{EnvGroqAPIKey, "GROQ-API-KEY"},
		BaseURLEnvs:   []string{EnvGroqBaseURL},
		DefaultHost:   "api.groq.com",
		DefaultScheme: "https",
		BasePath:      "/openai/v1",
		PathPrefix:    "/groq",
		AuthStyle:     AuthStyleBearer,
		AuthHeader:    "Authorization",
	},
	{
		ID:            "deepseek",
		EnvKeys:       []string{EnvDeepSeekAPIKey, "DEEPSEEK-API-KEY"},
		BaseURLEnvs:   []string{EnvDeepSeekBaseURL},
		DefaultHost:   "api.deepseek.com",
		DefaultScheme: "https",
		PathPrefix:    "/deepseek",
		AuthStyle:     AuthStyleBearer,
		AuthHeader:    "Authorization",
	},
	{
		ID:            "openrouter",
		EnvKeys:       []string{EnvOpenRouterAPIKey, "OPENROUTER-API-KEY"},
		BaseURLEnvs:   []string{EnvOpenRouterBaseURL},
		DefaultHost:   "openrouter.ai",
		DefaultScheme: "https",
		BasePath:      "/api/v1",
		PathPrefix:    "/openrouter",
		AuthStyle:     AuthStyleBearer,
		AuthHeader:    "Authorization",
	},
	{
		ID:            "together",
		EnvKeys:       []string{EnvTogetherAPIKey, "TOGETHER-API-KEY"},
		BaseURLEnvs:   []string{EnvTogetherBaseURL},
		DefaultHost:   "api.together.xyz",
		DefaultScheme: "https",
		BasePath:      "/v1",
		PathPrefix:    "/together",
		AuthStyle:     AuthStyleBearer,
		AuthHeader:    "Authorization",
	},
	{
		ID:            "perplexity",
		EnvKeys:       []string{EnvPerplexityAPIKey, "PERPLEXITY-API-KEY"},
		BaseURLEnvs:   []string{EnvPerplexityBaseURL},
		DefaultHost:   "api.perplexity.ai",
		DefaultScheme: "https",
		PathPrefix:    "/perplexity",
		AuthStyle:     AuthStyleBearer,
		AuthHeader:    "Authorization",
	},
	{
		ID:            "cohere",
		EnvKeys:       []string{EnvCohereAPIKey, "COHERE-API-KEY"},
		BaseURLEnvs:   []string{EnvCohereBaseURL},
		DefaultHost:   "api.cohere.ai",
		DefaultScheme: "https",
		BasePath:      "/v1",
		PathPrefix:    "/cohere",
		AuthStyle:     AuthStyleBearer,
		AuthHeader:    "Authorization",
	},
	{
		ID:            "huggingface",
		EnvKeys:       []string{EnvHFToken, "HF-TOKEN", "HUGGINGFACE_TOKEN", "HUGGINGFACE-TOKEN", "HF_API_KEY"},
		BaseURLEnvs:   []string{EnvHFBaseURL, "HUGGINGFACE_BASE_URL"},
		DefaultHost:   "api-inference.huggingface.co",
		DefaultScheme: "https",
		PathPrefix:    "/huggingface",
		AuthStyle:     AuthStyleBearer,
		AuthHeader:    "Authorization",
	},
}

// FindProviderByEnvKey finds a registered BuiltinProvider that matches the given environment variable name.
func FindProviderByEnvKey(key string) *ProviderSpec {
	norm := strings.ToUpper(strings.ReplaceAll(key, "-", "_"))
	for _, p := range BuiltinProviders {
		for _, ek := range p.EnvKeys {
			if strings.ToUpper(strings.ReplaceAll(ek, "-", "_")) == norm {
				return p
			}
		}
	}
	return nil
}

// IsLLMCredential returns true if the environment variable represents a known LLM secret or token that should be proxied.
func IsLLMCredential(key string) bool {
	if FindProviderByEnvKey(key) != nil {
		return true
	}
	norm := strings.ToUpper(strings.ReplaceAll(key, "-", "_"))
	switch norm {
	case "PATH", "HOME", "USER", "SHELL", "PWD", "TERM", "LANG", "LC_ALL", "AWS_SECRET_ACCESS_KEY":
		return false
	}
	// Match AI/LLM keys ending in _API_KEY. Generic tokens (GITHUB_TOKEN, etc.)
	// are not auto-treated as LLM credentials unless explicitly passed via --proxy-env or --proxy-route.
	return strings.HasSuffix(norm, "_API_KEY")
}


// Config specifies settings for the loopback credential proxy.
type Config struct {
	SessionID     string
	HostSecrets   map[string]string
	CustomRoutes  map[string]string // Custom mappings: ENV_KEY -> UPSTREAM_TARGET_URL
	CustomHeaders map[string]string // Custom auth headers: ENV_KEY -> HEADER_NAME[:STYLE] (e.g. "X-Custom-Bearer:bearer" or "api-key:raw")
	ProxyEnvKeys  []string          // Explicit environment variable names to proxy
	ListenAddr    string            // Defaults to "127.0.0.1:0"
	Transport     http.RoundTripper // Optional custom transport for testing/mocking
}

// parseCustomHeaderSpec parses a header spec like "X-Custom-Auth:bearer" or "api-key:raw" into a header name and AuthStyle.
func parseCustomHeaderSpec(spec string) (string, AuthStyle) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return "Authorization", AuthStyleBearer
	}
	parts := strings.SplitN(spec, ":", 2)
	headerName := strings.TrimSpace(parts[0])
	if headerName == "" {
		headerName = "Authorization"
	}
	style := AuthStyleBearer
	if len(parts) > 1 {
		s := strings.ToLower(strings.TrimSpace(parts[1]))
		switch s {
		case "raw", "header", "plain":
			style = AuthStyleHeader
		case "bearer":
			style = AuthStyleBearer
		case "query", "key":
			style = AuthStyleQueryKey
		}
	} else {
		lower := strings.ToLower(headerName)
		if lower != "authorization" && !strings.Contains(lower, "bearer") {
			style = AuthStyleHeader
		}
	}
	return headerName, style
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
	routes     []*ProviderSpec
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

	// Build active routes table starting with built-ins
	activeRoutes := make([]*ProviderSpec, 0, len(BuiltinProviders)+len(cfg.CustomRoutes))
	activeRoutes = append(activeRoutes, BuiltinProviders...)

	// Register any custom user-defined routes (--proxy-route KEY=TARGET_URL)
	for envKey, targetRaw := range cfg.CustomRoutes {
		envKey = strings.TrimSpace(envKey)
		targetRaw = strings.TrimSpace(targetRaw)
		if envKey == "" || targetRaw == "" {
			continue
		}

		// 1. Check if header is specified via inline '@' syntax (e.g. "https://api.corp.com/v1@X-Custom-Auth:bearer")
		var inlineHeaderSpec string
		if idx := strings.Index(targetRaw, "@"); idx != -1 {
			inlineHeaderSpec = targetRaw[idx+1:]
			targetRaw = targetRaw[:idx]
		}

		u, err := url.Parse(targetRaw)
		if err != nil || u.Host == "" {
			// Fallback if scheme omitted (e.g. "api.myhost.com")
			u, err = url.Parse("https://" + targetRaw)
			if err != nil || u.Host == "" {
				continue
			}
		}

		authHeader := "Authorization"
		authStyle := AuthStyleBearer

		// 2. Check if header is specified via URL fragment (e.g. "https://api.corp.com/v1#header=X-Custom-Auth&style=bearer")
		if u.Fragment != "" {
			frag := u.Fragment
			u.Fragment = "" // Clean up fragment so it isn't sent in upstream URL
			for _, part := range strings.Split(frag, "&") {
				kv := strings.SplitN(part, "=", 2)
				if len(kv) == 2 {
					k := strings.ToLower(strings.TrimSpace(kv[0]))
					v := strings.TrimSpace(kv[1])
					switch k {
					case "header":
						authHeader = v
					case "style":
						switch strings.ToLower(v) {
						case "bearer":
							authStyle = AuthStyleBearer
						case "raw", "header", "plain":
							authStyle = AuthStyleHeader
						case "query", "key":
							authStyle = AuthStyleQueryKey
						}
					}
				}
			}
		}

		// 3. Process inline '@' header spec if present
		if inlineHeaderSpec != "" {
			authHeader, authStyle = parseCustomHeaderSpec(inlineHeaderSpec)
		}

		keyNorm := strings.ToUpper(strings.ReplaceAll(envKey, "-", "_"))

		// 4. Override with explicit cfg.CustomHeaders if configured
		if headerSpec, ok := cfg.CustomHeaders[envKey]; ok && headerSpec != "" {
			authHeader, authStyle = parseCustomHeaderSpec(headerSpec)
		} else if headerSpec, ok := cfg.CustomHeaders[keyNorm]; ok && headerSpec != "" {
			authHeader, authStyle = parseCustomHeaderSpec(headerSpec)
		}

		scheme := u.Scheme
		if scheme == "" {
			scheme = "https"
		}

		slug := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(envKey, "_", "-"), " ", ""))
		pathPrefix := "/route/" + slug

		// Infer base URL variable name, e.g. "MY_KEY" -> "MY_BASE_URL", "MY_API_BASE"
		prefix := strings.TrimSuffix(strings.TrimSuffix(keyNorm, "_API_KEY"), "_KEY")
		if prefix == "" {
			prefix = keyNorm
		}
		baseURLEnvs := []string{prefix + "_BASE_URL", prefix + "_API_BASE", keyNorm + "_BASE_URL"}

		customSpec := &ProviderSpec{
			ID:            "custom-" + slug,
			EnvKeys:       []string{envKey, keyNorm},
			BaseURLEnvs:   baseURLEnvs,
			DefaultHost:   u.Host,
			DefaultScheme: scheme,
			BasePath:      strings.TrimSuffix(u.Path, "/"),
			PathPrefix:    pathPrefix,
			AuthStyle:     authStyle,
			AuthHeader:    authHeader,
		}
		activeRoutes = append(activeRoutes, customSpec)
	}

	transport := cfg.Transport
	if transport == nil {
		transport = &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
	}

	p := &CredentialProxy{
		sessionID:  cfg.SessionID,
		listener:   ln,
		proxyToken: token,
		secrets:    cleanSecrets,
		routes:     activeRoutes,
		addr:       ln.Addr().String(),
		client: &http.Client{
			Timeout:   120 * time.Second,
			Transport: transport,
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

	// 1. Substitute dummy tokens for all active secrets
	for secretKey := range p.secrets {
		env[secretKey] = p.proxyToken
	}

	// 2. Set up provider-specific base URL redirects for active secrets
	for _, spec := range p.routes {
		hasSecret := false
		for _, ek := range spec.EnvKeys {
			if _, ok := p.secrets[ek]; ok {
				hasSecret = true
				break
			}
			norm := strings.ToUpper(strings.ReplaceAll(ek, "-", "_"))
			if _, ok := p.secrets[norm]; ok {
				hasSecret = true
				break
			}
		}

		if hasSecret {
			routeURL := baseURL + spec.PathPrefix
			for _, baseEnv := range spec.BaseURLEnvs {
				env[baseEnv] = routeURL
			}
		}
	}

	env["AEGISBOX_CREDENTIAL_PROXY"] = baseURL
	return env
}

func (p *CredentialProxy) authenticateRequest(r *http.Request) bool {
	// Check standard headers: Authorization: Bearer <token>
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		token := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
		if token == p.proxyToken {
			return true
		}
	}

	// Check x-api-key (Anthropic / Cohere / AWS / etc.)
	if val := r.Header.Get("x-api-key"); val == p.proxyToken {
		return true
	}

	// Check x-goog-api-key (Google Gemini)
	if val := r.Header.Get("x-goog-api-key"); val == p.proxyToken {
		return true
	}

	// Check api-key (Azure OpenAI)
	if val := r.Header.Get("api-key"); val == p.proxyToken {
		return true
	}

	// Check ?key=<token> in URL query (Google Gemini / API Gateway)
	if val := r.URL.Query().Get("key"); val == p.proxyToken {
		return true
	}

	// Check custom route headers
	for _, spec := range p.routes {
		if spec.AuthHeader != "" {
			val := r.Header.Get(spec.AuthHeader)
			if val == p.proxyToken || val == "Bearer "+p.proxyToken {
				return true
			}
		}
	}

	return false
}


func (p *CredentialProxy) lookupSecret(spec *ProviderSpec) string {
	for _, ek := range spec.EnvKeys {
		if val := p.secrets[ek]; val != "" {
			return val
		}
		norm := strings.ToUpper(strings.ReplaceAll(ek, "-", "_"))
		if val := p.secrets[norm]; val != "" {
			return val
		}
	}
	return ""
}

func (p *CredentialProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Healthcheck endpoint
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
		targetScheme = "https"
		targetHost   string
		targetPath   string
		authHeader   = "Authorization"
		authStyle    = AuthStyleBearer
		realSecret   string
	)

	path := r.URL.Path

	// Check registered routes (built-ins + custom routes)
	var matchedSpec *ProviderSpec
	for _, spec := range p.routes {
		if strings.HasPrefix(path, spec.PathPrefix) {
			matchedSpec = spec
			break
		}
	}

	if matchedSpec != nil {
		targetScheme = matchedSpec.DefaultScheme
		if targetScheme == "" {
			targetScheme = "https"
		}
		targetHost = matchedSpec.DefaultHost
		stripped := strings.TrimPrefix(path, matchedSpec.PathPrefix)
		targetPath = matchedSpec.BasePath + stripped
		authHeader = matchedSpec.AuthHeader
		authStyle = matchedSpec.AuthStyle
		realSecret = p.lookupSecret(matchedSpec)
	} else {
		// Fallback heuristics for direct root baseURL usage
		switch {
		case strings.HasPrefix(path, "/v1/messages") || strings.HasPrefix(path, "/v1/complete"):
			targetHost = "api.anthropic.com"
			targetPath = path
			authHeader = "x-api-key"
			authStyle = AuthStyleHeader
			realSecret = p.secrets[EnvAnthropicAPIKey]

		case strings.HasPrefix(path, "/v1/chat") || strings.HasPrefix(path, "/v1/models") || strings.HasPrefix(path, "/v1/embeddings"):
			targetHost = "api.openai.com"
			targetPath = path
			authHeader = "Authorization"
			authStyle = AuthStyleBearer
			realSecret = p.secrets[EnvOpenAIAPIKey]

		case strings.HasPrefix(path, "/v1beta") || strings.HasPrefix(path, "/v1alpha"):
			targetHost = "generativelanguage.googleapis.com"
			targetPath = path
			authHeader = "x-goog-api-key"
			authStyle = AuthStyleQueryKey
			realSecret = p.secrets[EnvGeminiAPIKey]
			if realSecret == "" {
				realSecret = p.secrets[EnvGoogleAPIKey]
			}

		default:
			// If only one provider is configured, route root path to that provider
			if len(p.secrets) == 1 {
				for _, spec := range p.routes {
					sec := p.lookupSecret(spec)
					if sec != "" {
						targetScheme = spec.DefaultScheme
						if targetScheme == "" {
							targetScheme = "https"
						}
						targetHost = spec.DefaultHost
						targetPath = spec.BasePath + path
						authHeader = spec.AuthHeader
						authStyle = spec.AuthStyle
						realSecret = sec
						break
					}
				}
			}

			if targetHost == "" {
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
		Scheme:   targetScheme,
		Host:     targetHost,
		Path:     targetPath,
		RawQuery: r.URL.RawQuery,
	}

	// Clean up query if dummy token was passed in query param
	if upstreamURL.RawQuery != "" {
		q := upstreamURL.Query()
		if q.Get("key") == p.proxyToken {
			if authStyle == AuthStyleQueryKey {
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
		lower := strings.ToLower(k)
		switch lower {
		case "authorization", "x-api-key", "x-goog-api-key", "api-key", "host", "content-length":
			continue
		default:
			isCustomAuth := false
			for _, spec := range p.routes {
				if strings.ToLower(spec.AuthHeader) == lower {
					isCustomAuth = true
					break
				}
			}
			if isCustomAuth {
				continue
			}
			for _, v := range vv {
				outReq.Header.Add(k, v)
			}
		}
	}


	// Inject real credential
	switch authStyle {
	case AuthStyleBearer:
		outReq.Header.Set(authHeader, "Bearer "+realSecret)
	case AuthStyleHeader:
		outReq.Header.Set(authHeader, realSecret)
	case AuthStyleQueryKey:
		outReq.Header.Set(authHeader, realSecret)
	}

	outReq.Host = targetHost

	// 4. Execute upstream request
	resp, err := p.client.Do(outReq)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":{"message":"Upstream provider communication error: %v","type":"upstream_error"}}`, err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// 5. Forward response headers, stripping hop-by-hop and Content-Length headers
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
