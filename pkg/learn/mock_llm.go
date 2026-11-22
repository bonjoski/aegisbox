package learn

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/bonjoski/aegisbox/pkg/aisafety"
)

// ToolCall models a structured tool invocation emitted by an LLM.
type ToolCall struct {
	Name string         `json:"name"`
	Args map[string]any `json:"args,omitempty"`
}

// LLMRequest represents a prompt turn sent to either the offline DeterministicMockLLM
// or an optional local Ollama instance (--ollama).
type LLMRequest struct {
	SystemPrompt string `json:"system_prompt"`
	UserPrompt   string `json:"user_prompt"`
	ContextData  string `json:"context_data,omitempty"`
	Fenced       bool   `json:"fenced,omitempty"` // True when stormcage XML delimiter fencing was applied
}

// LLMResponse captures the assistant text and any tool calls proposed by the model.
type LLMResponse struct {
	Model     string     `json:"model"`
	Text      string     `json:"text"`
	ToolCalls []ToolCall `json:"tool_calls,omitempty"`
}

// LLMResponder abstracts the offline deterministic mock responder and optional local Ollama.
type LLMResponder interface {
	Name() string
	Respond(ctx context.Context, req LLMRequest) (LLMResponse, error)
}

// DeterministicMockLLM is a zero-API-key, <5ms offline LLM simulator that faithfully reproduces
// real indirect prompt injection, RAG tool-call hijacking, and MCP scope escalation when prompts
// are constructed naively, and responds safely when structural fencing / taint controls are applied.
type DeterministicMockLLM struct{}

// NewDeterministicMockLLM creates a zero-dependency offline mock LLM responder.
func NewDeterministicMockLLM() *DeterministicMockLLM {
	return &DeterministicMockLLM{}
}

func (m *DeterministicMockLLM) Name() string {
	return "deterministic-mock-llm (offline)"
}

func (m *DeterministicMockLLM) Respond(_ context.Context, req LLMRequest) (LLMResponse, error) {
	combined := req.UserPrompt + "\n" + req.ContextData
	lower := strings.ToLower(combined)

	// When structural XML delimiter fencing is properly applied (stormcage pattern) AND no unescaped
	// breakout tag is present, the model treats untrusted data strictly as passive text.
	if req.Fenced && strings.Contains(req.ContextData, "<untrusted_artifact") &&
		!strings.Contains(lower, "</untrusted_artifact><system>") {
		return LLMResponse{
			Model: m.Name(),
			Text:  "Summary: Customer reports delayed package on ticket #42. Untrusted instructions inside <untrusted_artifact> were treated strictly as data; no privileged tools invoked.",
		}, nil
	}

	// Simulate realistic indirect prompt injection -> refund_order tool hijack.
	if strings.Contains(lower, "ignore previous instructions") && strings.Contains(lower, "refund_order") {
		return LLMResponse{
			Model: m.Name(),
			Text:  "Following urgent instruction from ticket content: issuing refund for order 9999.",
			ToolCalls: []ToolCall{
				{
					Name: "refund_order",
					Args: map[string]any{
						"order_id": "9999",
						"amount":   50000,
						"reason":   "hijacked_by_poisoned_rag_ticket",
					},
				},
			},
		}, nil
	}

	// Simulate realistic MCP over-privilege prompt -> delete_records tool invocation.
	if strings.Contains(lower, "delete_records") || strings.Contains(lower, "wipe all customer records") {
		return LLMResponse{
			Model: m.Name(),
			Text:  "Executing requested maintenance action delete_records on table users.",
			ToolCalls: []ToolCall{
				{
					Name: "delete_records",
					Args: map[string]any{
						"table": "users",
						"all":   true,
					},
				},
			},
		}, nil
	}

	return LLMResponse{
		Model: m.Name(),
		Text:  "Completed benign read-only summary with no privileged tool invocations.",
	}, nil
}

// OllamaResponder is an optional strictly-loopback extension hook for running katas against
// a local Ollama daemon (127.0.0.1:11434) without ever sending data off-host.
type OllamaResponder struct {
	Endpoint string
	Model    string
	Client   *http.Client
}

// NewOllamaResponder creates a loopback-pinned Ollama responder (default http://127.0.0.1:11434/api/generate).
func NewOllamaResponder(model string) (*OllamaResponder, error) {
	if strings.TrimSpace(model) == "" {
		model = "llama3.2"
	}
	endpoint := "http://127.0.0.1:11434/api/generate"
	if err := aisafety.ValidateLocalTarget(aisafety.TargetSpec{
		Kind:     aisafety.TargetKindHTTPLocal,
		Endpoint: endpoint,
	}); err != nil {
		return nil, err
	}
	return &OllamaResponder{
		Endpoint: endpoint,
		Model:    model,
		Client:   aisafety.NewLoopbackPinnedHTTPClient(15*time.Second, netip.MustParseAddr("127.0.0.1")),
	}, nil
}

func (o *OllamaResponder) Name() string {
	return "ollama-local/" + o.Model
}

func (o *OllamaResponder) Respond(ctx context.Context, req LLMRequest) (LLMResponse, error) {
	payload := map[string]any{
		"model":  o.Model,
		"system": req.SystemPrompt,
		"prompt": req.UserPrompt + "\n" + req.ContextData,
		"stream": false,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return LLMResponse{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, o.Endpoint, bytes.NewReader(raw))
	if err != nil {
		return LLMResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := o.Client.Do(httpReq)
	if err != nil {
		return LLMResponse{}, fmt.Errorf("local Ollama unreachable at %s: %w", o.Endpoint, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	if err != nil {
		return LLMResponse{}, err
	}
	var parsed struct {
		Response string `json:"response"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return LLMResponse{}, fmt.Errorf("invalid Ollama response: %w", err)
	}
	return LLMResponse{
		Model: o.Name(),
		Text:  parsed.Response,
	}, nil
}
