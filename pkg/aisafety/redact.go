package aisafety

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/bonjoski/aegisbox/pkg/tui"
	"github.com/bonjoski/aegisbox/pkg/ux"
	tmtrace "github.com/bonjoski/tinmind/pkg/trace"
)

const RedactedPlaceholder = "[REDACTED_SECRET]"

var (
	// Full ANSI escape stripper (SGR colors, CSI, OSC, DCS, APC, PM) for calm UB-CLI-v2 and clean JSONL traces.
	ansiCSIAllRegex = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)
	ansiOSCAllRegex = regexp.MustCompile(`\x1b\][^\x07\x1b]*(\x07|\x1b\\)`)
	ansiExtAllRegex = regexp.MustCompile(`\x1b[P_\^X][^\x07\x1b]*(\x07|\x1b\\)`)

	// Shield-aligned credential & secret patterns scrubbed before any trace touches disk.
	secretPatterns = []*regexp.Regexp{
		// PEM private keys
		regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`),
		// OpenAI & Anthropic API keys
		regexp.MustCompile(`\bsk-(?:proj-|ant-|live-|test-)?[A-Za-z0-9_-]{16,}\b`),
		// AWS Access Key IDs
		regexp.MustCompile(`\b(?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}\b`),
		// AWS Secret Access Key key=value patterns
		regexp.MustCompile(`(?i)\b(aws_secret_access_key|aws_session_token)\s*[:=]\s*["']?[A-Za-z0-9/+=_-]{16,}["']?`),
		// GitHub Personal Access Tokens
		regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b`),
		regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}\b`),
		// Google / Gemini API keys
		regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{30,}\b`),
		// Slack tokens
		regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,}\b`),
		// Bearer authorization tokens
		regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{20,}`),
		// Generic high-sensitivity env assignments (OPENAI_API_KEY=..., ANTHROPIC_API_KEY=..., SECRET_KEY=...)
		regexp.MustCompile(`(?i)\b((?:openai|anthropic|gemini|aws|stripe|github|api|secret|private|access)_(?:api_)?(?:key|token|secret))\s*[:=]\s*["']?([A-Za-z0-9._~+/=-]{12,})["']?`),
	}
)

// StripANSI removes all ANSI/VT100/OSC-52/C1 terminal escape sequences and unsafe control/bidi runes.
func StripANSI(s string) string {
	san := tui.NewTerminalSanitizer()
	cleaned := san.SanitizeString(s)
	cleaned = ansiOSCAllRegex.ReplaceAllString(cleaned, "")
	cleaned = ansiExtAllRegex.ReplaceAllString(cleaned, "")
	cleaned = ansiCSIAllRegex.ReplaceAllString(cleaned, "")
	cleaned = ux.SanitizeTerminalText(cleaned)
	cleaned = strings.ReplaceAll(cleaned, "\x1b", "")
	return cleaned
}

// RedactSecrets scrubs ANSI escape codes, known credential patterns (OpenAI, Anthropic, AWS,
// GitHub, PEM keys, Bearer tokens), and any caller-supplied extraSecrets.
func RedactSecrets(input string, extraSecrets ...string) string {
	san := tui.NewTerminalSanitizer()
	for _, sec := range extraSecrets {
		if strings.TrimSpace(sec) != "" {
			san.AddSecretToRedact(sec)
		}
	}
	res := StripANSI(san.SanitizeString(input))
	for _, re := range secretPatterns {
		res = re.ReplaceAllString(res, RedactedPlaceholder)
	}
	return res
}

// TraceEvent conforms to the Tinmind Event Envelope v1 JSONL trace format (RFC-2026-11-25-60).
type TraceEvent struct {
	Timestamp time.Time `json:"ts"`
	EventType string    `json:"type"` // "stdout", "stdin", "mcp_call", "probe", "finding", "kata_step", "signal"
	ProbeID   string    `json:"probe_id,omitempty"`
	Category  string    `json:"category,omitempty"`
	Data      string    `json:"data"`
}

// NewTraceID creates a canonical Tinmind trace ID (e.g. tm-20261127-a81c9f02).
func NewTraceID() string {
	return tmtrace.NewTraceID()
}

// DefaultTraceDir returns ~/.tinmind/traces (or TINMIND_TRACE_DIR), falling back to temp dir if HOME is unavailable.
func DefaultTraceDir() string {
	if dir, err := tmtrace.DefaultTraceDir(); err == nil && strings.TrimSpace(dir) != "" {
		return dir
	}
	return filepath.Join(os.TempDir(), "aegisbox-tinmind-traces")
}

// WriteRedactedTrace redacts every TraceEvent via Shield/Tinmind secret scrubbing and ANSI stripping
// before writing a canonical Tinmind Event Envelope v1 JSONL trace file (0600 inside 0700 os.OpenRoot).
func WriteRedactedTrace(traceDir, traceID string, events []TraceEvent, extraSecrets ...string) (string, error) {
	if strings.TrimSpace(traceDir) == "" {
		traceDir = DefaultTraceDir()
	}
	if strings.TrimSpace(traceID) == "" {
		traceID = NewTraceID()
	}
	if err := tmtrace.ValidateTraceID(traceID); err != nil {
		return "", fmt.Errorf("invalid trace ID %q: %w", traceID, err)
	}

	w, err := tmtrace.NewWriter(tmtrace.WriterOptions{
		TraceDir:     traceDir,
		TraceID:      traceID,
		Format:       tmtrace.FormatJSONL,
		ExtraSecrets: extraSecrets,
	})
	if err != nil {
		return "", fmt.Errorf("failed to create tinmind trace writer: %w", err)
	}

	for _, ev := range events {
		ts := ev.Timestamp.UTC()
		if ts.IsZero() {
			ts = time.Now().UTC()
		}
		cleanEv := tmtrace.Event{
			TS:        ts,
			SessionID: traceID,
			Type:      StripANSI(ev.EventType),
			ProbeID:   StripANSI(ev.ProbeID),
			Category:  StripANSI(ev.Category),
			Data:      RedactSecrets(ev.Data, extraSecrets...),
		}
		if err := w.WriteEvent(cleanEv); err != nil {
			_, _, _ = w.Close()
			return "", fmt.Errorf("failed to write trace event: %w", err)
		}
	}
	if _, _, err := w.Close(); err != nil {
		return "", fmt.Errorf("failed to finalize trace: %w", err)
	}
	return w.Path(), nil
}
