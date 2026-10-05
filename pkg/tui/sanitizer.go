package tui

import (
	"bytes"
	"io"
	"regexp"
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
type TerminalSanitizer struct{}

// NewTerminalSanitizer creates a new TerminalSanitizer.
func NewTerminalSanitizer() *TerminalSanitizer {
	return &TerminalSanitizer{}
}

// SanitizeString cleans a raw string from untrusted terminal output,
// stripping OSC 52 clipboard hijack codes, dangerous escape sequences,
// and screen-hiding controls while preserving standard colors and text.
func (s *TerminalSanitizer) SanitizeString(input string) string {
	b := []byte(input)
	cleaned := s.SanitizeBytes(b)
	return string(cleaned)
}

// SanitizeBytes cleans raw byte slices from untrusted terminal output.
func (s *TerminalSanitizer) SanitizeBytes(input []byte) []byte {
	// 1. Strip OSC sequences (OSC 52 clipboard, window title, etc.)
	res := oscRegex.ReplaceAll(input, nil)

	// 2. Strip DCS, APC, PM sequences
	res = extEscRegex.ReplaceAll(res, nil)

	// 3. Strip cursor position / clear screen commands that can disguise output
	res = csiCursorRegex.ReplaceAll(res, nil)

	// 4. Strip dangerous non-printable control characters (except \n, \r, \t, and \x1b)
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
