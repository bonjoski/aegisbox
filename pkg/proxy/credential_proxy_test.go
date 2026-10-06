package proxy_test

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/bonjoski/aegisbox/pkg/proxy"
)

// roundTripFunc implements http.RoundTripper for mock in-memory upstream inspection.
type roundTripFunc func(req *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestCredentialProxy_IsLLMCredential(t *testing.T) {
	valid := []string{
		"ANTHROPIC_API_KEY",
		"anthropic_api_key",
		"ANTHROPIC-API-KEY",
		"OPENAI_API_KEY",
		"openai-api-key",
		"GEMINI_API_KEY",
		"gemini-api-key",
		"GEMINI-API-KEY",
		"GOOGLE_API_KEY",
		"google-api-key",
	}
	for _, k := range valid {
		if !proxy.IsLLMCredential(k) {
			t.Errorf("expected IsLLMCredential(%q) to be true", k)
		}
	}

	invalid := []string{
		"AWS_SECRET_ACCESS_KEY",
		"GITHUB_TOKEN",
		"DATABASE_URL",
		"PATH",
		"HOME",
	}
	for _, k := range invalid {
		if proxy.IsLLMCredential(k) {
			t.Errorf("expected IsLLMCredential(%q) to be false", k)
		}
	}
}

func TestCredentialProxy_AuthAndTokenSubstitution(t *testing.T) {
	const realAnthropicKey = "sk-ant-live-real-secret-123456"

	p, err := proxy.NewCredentialProxy(proxy.Config{
		SessionID: "test-sess",
		HostSecrets: map[string]string{
			proxy.EnvAnthropicAPIKey: realAnthropicKey,
		},
	})
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}
	defer p.Close()
	p.Start()

	// 1. Invariant: SandboxEnv NEVER exposes the real secret
	sandboxEnv := p.SandboxEnv()
	if sandboxEnv[proxy.EnvAnthropicAPIKey] == realAnthropicKey {
		t.Fatalf("CRITICAL SECURITY VIOLATION: Real API key exposed in SandboxEnv()!")
	}
	if !strings.HasPrefix(sandboxEnv[proxy.EnvAnthropicAPIKey], "aegis-tok-") {
		t.Fatalf("expected ephemeral proxy token, got: %s", sandboxEnv[proxy.EnvAnthropicAPIKey])
	}
	if !strings.Contains(sandboxEnv[proxy.EnvAnthropicBaseURL], p.BaseURL()) {
		t.Fatalf("expected ANTHROPIC_BASE_URL to point to loopback proxy, got: %s", sandboxEnv[proxy.EnvAnthropicBaseURL])
	}

	// 2. Healthcheck endpoint
	healthResp, err := http.Get(p.BaseURL() + "/healthz")
	if err != nil {
		t.Fatalf("healthz request failed: %v", err)
	}
	defer healthResp.Body.Close()
	if healthResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK from healthz, got %d", healthResp.StatusCode)
	}

	// 3. Unauthorized request (invalid or missing proxy token) must be rejected with 401
	unauthReq, _ := http.NewRequest("POST", p.BaseURL()+"/anthropic/v1/messages", strings.NewReader(`{}`))
	unauthReq.Header.Set("x-api-key", "invalid-token-here")
	unauthResp, err := http.DefaultClient.Do(unauthReq)
	if err != nil {
		t.Fatalf("unauthorized request error: %v", err)
	}
	defer unauthResp.Body.Close()
	if unauthResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for invalid proxy token, got: %d", unauthResp.StatusCode)
	}
}

func TestCredentialProxy_GeminiRoundTrip_HeaderAndQuery(t *testing.T) {
	const realGeminiKey = "AIzaSyRealSecretKey12345"

	var (
		interceptedAuthHeader string
		interceptedQueryKey   string
		interceptedHost       string
		interceptedPath       string
		interceptedBody       string
	)

	mockTransport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		interceptedHost = req.Host
		interceptedPath = req.URL.Path
		interceptedAuthHeader = req.Header.Get("x-goog-api-key")
		interceptedQueryKey = req.URL.Query().Get("key")
		bodyBytes, _ := io.ReadAll(req.Body)
		interceptedBody = string(bodyBytes)

		respBody := `{"candidates":[{"content":{"parts":[{"text":"Hello from Gemini mock"}]}}]}`
		return &http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Content-Type": []string{"application/json"},
			},
			Body: io.NopCloser(bytes.NewBufferString(respBody)),
		}, nil
	})

	// Test with hyphenated Locksmith convention GEMINI-API-KEY
	p, err := proxy.NewCredentialProxy(proxy.Config{
		SessionID: "gemini-sess",
		HostSecrets: map[string]string{
			"GEMINI-API-KEY": realGeminiKey,
		},
		Transport: mockTransport,
	})
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}
	defer p.Close()
	p.Start()

	proxyToken := p.ProxyToken()
	if !strings.HasPrefix(proxyToken, "aegis-tok-") {
		t.Fatalf("expected token starting with aegis-tok-, got: %s", proxyToken)
	}

	// 1. Send request with dummy token in URL query AND in header
	reqURL := fmt.Sprintf("%s/gemini/v1beta/models/gemini-flash-latest:generateContent?key=%s", p.BaseURL(), proxyToken)
	reqBody := `{"contents":[{"parts":[{"text":"ping"}]}]}`
	req, err := http.NewRequest("POST", reqURL, strings.NewReader(reqBody))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-goog-api-key", proxyToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("proxy request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200 OK, got %d: %s", resp.StatusCode, string(body))
	}

	respBytes, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(respBytes), "Hello from Gemini mock") {
		t.Errorf("unexpected response body: %s", string(respBytes))
	}

	// Upstream verifications
	if interceptedHost != "generativelanguage.googleapis.com" {
		t.Errorf("expected host generativelanguage.googleapis.com, got: %s", interceptedHost)
	}
	if interceptedPath != "/v1beta/models/gemini-flash-latest:generateContent" {
		t.Errorf("expected path without /gemini prefix, got: %s", interceptedPath)
	}
	if interceptedAuthHeader != realGeminiKey {
		t.Errorf("CRITICAL: expected upstream x-goog-api-key to be real secret, got: %s", interceptedAuthHeader)
	}
	if interceptedQueryKey != realGeminiKey {
		t.Errorf("CRITICAL: expected upstream query ?key= to be real secret, got: %s", interceptedQueryKey)
	}
	if interceptedBody != reqBody {
		t.Errorf("expected body to match, got: %s", interceptedBody)
	}
	if p.RequestCount() != 1 {
		t.Errorf("expected audit count 1, got %d", p.RequestCount())
	}
}

func TestCredentialProxy_OpenAIRoundTrip(t *testing.T) {
	const realOpenAIKey = "sk-live-openai-secret-token"

	var (
		interceptedAuthHeader string
		interceptedHost       string
		interceptedPath       string
	)

	mockTransport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		interceptedHost = req.Host
		interceptedPath = req.URL.Path
		interceptedAuthHeader = req.Header.Get("Authorization")

		return &http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Content-Type": []string{"application/json"},
			},
			Body: io.NopCloser(bytes.NewBufferString(`{"id":"chatcmpl-123"}`)),
		}, nil
	})

	p, err := proxy.NewCredentialProxy(proxy.Config{
		SessionID: "openai-sess",
		HostSecrets: map[string]string{
			"OPENAI-API-KEY": realOpenAIKey,
		},
		Transport: mockTransport,
	})
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}
	defer p.Close()
	p.Start()

	proxyToken := p.ProxyToken()

	reqURL := fmt.Sprintf("%s/openai/v1/chat/completions", p.BaseURL())
	req, err := http.NewRequest("POST", reqURL, strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	// Sandbox sends Authorization: Bearer <aegis-tok-...>
	req.Header.Set("Authorization", "Bearer "+proxyToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	if interceptedHost != "api.openai.com" {
		t.Errorf("expected api.openai.com, got: %s", interceptedHost)
	}
	if interceptedPath != "/v1/chat/completions" {
		t.Errorf("expected /v1/chat/completions, got: %s", interceptedPath)
	}
	expectedAuth := "Bearer " + realOpenAIKey
	if interceptedAuthHeader != expectedAuth {
		t.Errorf("expected %s, got: %s", expectedAuth, interceptedAuthHeader)
	}
}

func TestCredentialProxy_HopByHopAndStreaming(t *testing.T) {
	mockTransport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Content-Type":      []string{"text/event-stream"},
				"Connection":        []string{"keep-alive"},
				"Transfer-Encoding": []string{"chunked"},
				"Content-Length":    []string{"99999"}, // Stale content-length
			},
			Body: io.NopCloser(bytes.NewBufferString("data: chunk1\n\ndata: chunk2\n\n")),
		}, nil
	})

	p, err := proxy.NewCredentialProxy(proxy.Config{
		SessionID: "stream-sess",
		HostSecrets: map[string]string{
			proxy.EnvAnthropicAPIKey: "sk-ant-test",
		},
		Transport: mockTransport,
	})
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}
	defer p.Close()
	p.Start()

	req, _ := http.NewRequest("POST", p.BaseURL()+"/anthropic/v1/messages", strings.NewReader(`{}`))
	req.Header.Set("x-api-key", p.ProxyToken())

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("streaming request failed: %v", err)
	}
	defer resp.Body.Close()

	// Verify hop-by-hop headers were stripped
	if resp.Header.Get("Connection") != "" {
		t.Errorf("expected Connection header to be stripped, got: %s", resp.Header.Get("Connection"))
	}
	if resp.Header.Get("Transfer-Encoding") != "" {
		t.Errorf("expected Transfer-Encoding header to be stripped, got: %s", resp.Header.Get("Transfer-Encoding"))
	}

	bodyBytes, _ := io.ReadAll(resp.Body)
	expected := "data: chunk1\n\ndata: chunk2\n\n"
	if string(bodyBytes) != expected {
		t.Errorf("expected %q, got: %q", expected, string(bodyBytes))
	}
}

func TestCredentialProxy_MultiProviderRouting(t *testing.T) {
	p, err := proxy.NewCredentialProxy(proxy.Config{
		SessionID: "multi-sess",
		HostSecrets: map[string]string{
			proxy.EnvAnthropicAPIKey: "sk-ant-anthropic-key",
			proxy.EnvOpenAIAPIKey:    "sk-openai-key",
			proxy.EnvGeminiAPIKey:    "aiza-gemini-key",
		},
	})
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}
	defer p.Close()

	env := p.SandboxEnv()
	if env[proxy.EnvAnthropicAPIKey] != p.ProxyToken() {
		t.Errorf("expected anthropic token to match proxy token")
	}
	if env[proxy.EnvOpenAIAPIKey] != p.ProxyToken() {
		t.Errorf("expected openai token to match proxy token")
	}
	if env[proxy.EnvGeminiAPIKey] != p.ProxyToken() {
		t.Errorf("expected gemini token to match proxy token")
	}

	if !strings.HasSuffix(env[proxy.EnvAnthropicBaseURL], "/anthropic") {
		t.Errorf("expected anthropic base url suffix /anthropic, got: %s", env[proxy.EnvAnthropicBaseURL])
	}
	if !strings.HasSuffix(env[proxy.EnvOpenAIBaseURL], "/openai/v1") {
		t.Errorf("expected openai base url suffix /openai/v1, got: %s", env[proxy.EnvOpenAIBaseURL])
	}
	if !strings.HasSuffix(env[proxy.EnvGeminiAPIBase], "/gemini") {
		t.Errorf("expected gemini base url suffix /gemini, got: %s", env[proxy.EnvGeminiAPIBase])
	}
}
