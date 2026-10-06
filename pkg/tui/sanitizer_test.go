package tui

import (
	"bytes"
	"strings"
	"testing"
)

func TestTerminalSanitizer_OSC52ClipboardStrip(t *testing.T) {
	sanitizer := NewTerminalSanitizer()

	// Malicious OSC 52 payload attempting to set host clipboard to "sudo rm -rf /"
	maliciousInput := "Hello World\x1b]52;c;c3VkbyBybSAtcmYgLyo=\x07 malicious attempt"
	cleaned := sanitizer.SanitizeString(maliciousInput)

	if strings.Contains(cleaned, "52;c;") || strings.Contains(cleaned, "\x1b]52") {
		t.Errorf("expected OSC 52 sequence to be stripped, got: %q", cleaned)
	}
	if !strings.Contains(cleaned, "Hello World") || !strings.Contains(cleaned, "malicious attempt") {
		t.Errorf("expected legitimate text preserved, got: %q", cleaned)
	}

	// ST terminated OSC sequence (\x1b\\)
	maliciousST := "Normal\x1b]0;Title Hijack\x1b\\ Text"
	cleanedST := sanitizer.SanitizeString(maliciousST)
	if strings.Contains(cleanedST, "Title Hijack") {
		t.Errorf("expected OSC window title to be stripped, got: %q", cleanedST)
	}
}

func TestTerminalSanitizer_PreserveColors(t *testing.T) {
	sanitizer := NewTerminalSanitizer()

	coloredInput := "\x1b[32mSUCCESS:\x1b[0m Operation completed \x1b[1;31mERROR\x1b[0m"
	cleaned := sanitizer.SanitizeString(coloredInput)

	if cleaned != coloredInput {
		t.Errorf("expected ANSI colors to be preserved, got %q, want %q", cleaned, coloredInput)
	}
}

func TestTerminalSanitizer_StripCursorRewriting(t *testing.T) {
	sanitizer := NewTerminalSanitizer()

	// Cursor line clear \x1b[2K and move \x1b[1A
	hiddenAttack := "Real Command\x1b[2K\x1b[1AFake Command"
	cleaned := sanitizer.SanitizeString(hiddenAttack)

	if strings.Contains(cleaned, "\x1b[2K") || strings.Contains(cleaned, "\x1b[1A") {
		t.Errorf("expected cursor movements stripped, got: %q", cleaned)
	}
}

func TestSanitizedWriter(t *testing.T) {
	var buf bytes.Buffer
	w := NewSanitizedWriter(&buf)

	payload := []byte("Compiling...\x1b]52;c;evil\x07Done!\n")
	n, err := w.Write(payload)
	if err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}
	if n != len(payload) {
		t.Errorf("expected bytes written %d, got %d", len(payload), n)
	}

	out := buf.String()
	if strings.Contains(out, "evil") || strings.Contains(out, "52;c") {
		t.Errorf("expected sanitized buffer, got: %q", out)
	}
	if !strings.Contains(out, "Compiling...Done!\n") {
		t.Errorf("expected preserved text, got: %q", out)
	}
}

func TestTerminalSanitizer_SecretRedaction(t *testing.T) {
	sanitizer := NewTerminalSanitizer()
	sanitizer.AddSecretToRedact("sk-ant-api03-secretkey-12345")

	output := "Connecting to API with token sk-ant-api03-secretkey-12345 ... Done"
	cleaned := sanitizer.SanitizeString(output)

	if strings.Contains(cleaned, "sk-ant-api03-secretkey-12345") {
		t.Errorf("expected secret to be redacted, got: %s", cleaned)
	}
	if !strings.Contains(cleaned, "[REDACTED_SECRET]") {
		t.Errorf("expected [REDACTED_SECRET] placeholder, got: %s", cleaned)
	}
}
