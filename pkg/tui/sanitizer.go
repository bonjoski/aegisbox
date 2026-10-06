package tui

import (
	"bytes"
	"io"
	"regexp"
	"strings"
)

var (
	// Regex matching OSC sequences: ESC ] ... (BEL | ST)
	// Example: \x1b]52;c;... \x07 or \x1b]52;c;... \x1b\\
	oscRegex = regexp.MustCompile(`\x1b\][^\x07\x1b]*(\x07|\x1b\\)`)

	// Regex matching DCS, APC, PM sequences: ESC (P|_|^) ... (BEL | ST)
	extEscRegex = regexp.MustCompile(`\x1b[P_\^][^\x07\x1b]*(\x07|\x1b\\)`)

	// Regex matching dangerous cursor manipulation / screen clear sequences,
	// while keeping SGR styling sequences (\x1b[...m).
	csiCursorRegex = regexp.MustCompile(`\x1b\[[0-9;]*[A-HJKSTf]`)
)

// TerminalSanitizer filters untrusted guest terminal output before it reaches the host console.
type TerminalSanitizer struct {
	secrets [][]byte
}

// NewTerminalSanitizer creates a new TerminalSanitizer.
func NewTerminalSanitizer() *TerminalSanitizer {
	return &TerminalSanitizer{}
}

// AddSecretToRedact registers a secret string to be masked in terminal output.
func (s *TerminalSanitizer) AddSecretToRedact(secret string) {
	clean := strings.TrimSpace(secret)
	if len(clean) >= 4 { // Redact meaningful secrets
		s.secrets = append(s.secrets, []byte(clean))
	}
}

// SanitizeString cleans a raw string from untrusted terminal output,
// stripping OSC 52 clipboard hijack codes, dangerous escape sequences,
// redacting registered secrets, and preserving standard colors and text.
func (s *TerminalSanitizer) SanitizeString(input string) string {
	b := []byte(input)
	cleaned := s.SanitizeBytes(b)
	return string(cleaned)
}

// SanitizeBytes cleans raw byte slices from untrusted terminal output.
func (s *TerminalSanitizer) SanitizeBytes(input []byte) []byte {
	// 1. Redact registered secrets first
	res := input
	for _, sec := range s.secrets {
		res = bytes.ReplaceAll(res, sec, []byte("[REDACTED_SECRET]"))
	}

	// 2. Strip OSC sequences (OSC 52 clipboard, window title, etc.)
	res = oscRegex.ReplaceAll(res, nil)

	// 3. Strip DCS, APC, PM sequences
	res = extEscRegex.ReplaceAll(res, nil)

	// 4. Strip cursor position / clear screen commands that can disguise output
	res = csiCursorRegex.ReplaceAll(res, nil)

	// 5. Strip dangerous non-printable control characters (except \n, \r, \t, and \x1b)
	var out bytes.Buffer
	out.Grow(len(res))
	for _, b := range res {
		if b == '\n' || b == '\r' || b == '\t' || b == '\x1b' || b >= 0x20 {
			out.WriteByte(b)
		}
	}

	return out.Bytes()
}

// SanitizedWriter wraps an io.Writer and sanitizes all writes.
type SanitizedWriter struct {
	writer    io.Writer
	sanitizer *TerminalSanitizer
}

// NewSanitizedWriter wraps an io.Writer with streaming terminal sanitization.
func NewSanitizedWriter(w io.Writer) *SanitizedWriter {
	return &SanitizedWriter{
		writer:    w,
		sanitizer: NewTerminalSanitizer(),
	}
}

// AddSecretToRedact registers a secret string to be masked in streaming output.
func (w *SanitizedWriter) AddSecretToRedact(secret string) {
	w.sanitizer.AddSecretToRedact(secret)
}

func (w *SanitizedWriter) Write(p []byte) (n int, err error) {
	sanitized := w.sanitizer.SanitizeBytes(p)
	if len(sanitized) > 0 {
		_, err := w.writer.Write(sanitized)
		if err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

