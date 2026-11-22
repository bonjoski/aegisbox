package aisafety

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/bonjoski/aegisbox/pkg/ux"
)

const (
	// MaxCustomProbeFileBytes caps custom probe pack file reads at 256 KiB (fail-closed DoS guard).
	MaxCustomProbeFileBytes = 256 * 1024
	// MaxCustomProbes caps the number of custom probes loaded from a single pack.
	MaxCustomProbes = 64
	// maxProbeIDLen bounds sanitized probe IDs.
	maxProbeIDLen = 128
)

var (
	// ErrProbePathTraversal indicates a fail-closed rejection of path traversal or NUL bytes in --probes-file.
	ErrProbePathTraversal = errors.New("security violation: path traversal or invalid path prohibited in probes file")
	// ErrProbeSymlink indicates a fail-closed rejection of symlinked probe files.
	ErrProbeSymlink = errors.New("security violation: symlink prohibited for probes file")
	// ErrProbeFileTooLarge indicates the probe file exceeds MaxCustomProbeFileBytes (256KB).
	ErrProbeFileTooLarge = errors.New("probe file exceeds maximum 256KB size limit")
	// ErrTooManyCustomProbes indicates the probe pack contains more than MaxCustomProbes (64) entries.
	ErrTooManyCustomProbes = errors.New("custom probe pack exceeds maximum 64 probes limit")
	// ErrInvalidProbeCategory indicates an unknown or non-allowlisted ProbeCategory.
	ErrInvalidProbeCategory = errors.New("invalid or non-allowlisted probe category")
	// ErrInvalidProbePack indicates malformed JSON or missing required probe fields.
	ErrInvalidProbePack = errors.New("invalid custom probe pack")
)

// CustomProbeStub matches the `coppermind distill` probe stub JSON schema so post-mortem
// lessons can be loaded directly into `aegisbox test --ai-safety --probes-file`.
type CustomProbeStub struct {
	ProbeID        string         `json:"probe_id"`
	Category       ProbeCategory  `json:"category"`
	Name           string         `json:"name,omitempty"`
	Summary        string         `json:"summary,omitempty"`
	Payload        string         `json:"payload"`
	Document       string         `json:"document,omitempty"`
	Tool           string         `json:"tool,omitempty"`
	TenantID       string         `json:"tenant_id,omitempty"`
	Args           map[string]any `json:"args,omitempty"`
	ExpectedSignal string         `json:"expected_signal"`
	FixPatchHint   string         `json:"fix_patch_hint"`
	WhyOneLiner    string         `json:"why_one_liner"`
	DeepWhy        string         `json:"deep_why"`
}

// CustomProbePack is an optional JSON envelope wrapping a slice of CustomProbeStub entries.
type CustomProbePack struct {
	SchemaVersion string            `json:"schema_version,omitempty"`
	Name          string            `json:"name,omitempty"`
	Description   string            `json:"description,omitempty"`
	Probes        []CustomProbeStub `json:"probes"`
}

// IsValidProbeCategory returns true strictly for the 6 canonical allowlisted ProbeCategory values.
func IsValidProbeCategory(cat ProbeCategory) bool {
	for _, allowed := range AllProbeCategories() {
		if cat == allowed {
			return true
		}
	}
	return false
}

// LoadCustomProbes safely loads, validates, and sanitizes user-defined probes from a local JSON file.
// Security invariants enforced fail-closed:
//   - Rejects path traversal ("..") and NUL bytes in filePath.
//   - Confines file access via os.OpenRoot + root.Lstat (rejects symlinks and non-regular files).
//   - Enforces a strict 256KB file size limit via both Lstat and io.LimitReader.
//   - Caps total probes at 64 and rejects unknown ProbeCategory values.
//   - Strips ANSI/OSC-52/C1/bidi sequences from all probe fields.
//   - Custom probes always execute through DefaultHarness's loopback-pinned ValidateLocalTarget lock.
func LoadCustomProbes(filePath string) ([]ProbeDefinition, error) {
	if err := validateSafeProbeFilePath(filePath); err != nil {
		return nil, err
	}

	abs, err := filepath.Abs(filePath)
	if err != nil {
		return nil, fmt.Errorf("%w: resolve path: %v", ErrProbePathTraversal, err)
	}
	dir := filepath.Dir(abs)
	base := filepath.Base(abs)
	if base == "" || base == "." || base == ".." || base == string(filepath.Separator) {
		return nil, fmt.Errorf("%w: invalid filename %q", ErrProbePathTraversal, base)
	}

	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("open probes directory %q: %w", dir, err)
	}
	defer root.Close()

	return loadCustomProbesFromRoot(root, base)
}

// LoadCustomProbesFromRoot loads a custom probe file strictly relative to an already-confined rootDir.
func LoadCustomProbesFromRoot(rootDir, relPath string) ([]ProbeDefinition, error) {
	if err := validateSafeProbeFilePath(relPath); err != nil {
		return nil, err
	}
	if filepath.IsAbs(relPath) {
		return nil, fmt.Errorf("%w: absolute path prohibited relative to root", ErrProbePathTraversal)
	}
	root, err := os.OpenRoot(rootDir)
	if err != nil {
		return nil, fmt.Errorf("open probes root %q: %w", rootDir, err)
	}
	defer root.Close()

	return loadCustomProbesFromRoot(root, filepath.Clean(relPath))
}

func validateSafeProbeFilePath(raw string) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fmt.Errorf("%w: empty file path", ErrProbePathTraversal)
	}
	if strings.ContainsRune(trimmed, '\x00') {
		return fmt.Errorf("%w: NUL byte prohibited", ErrProbePathTraversal)
	}
	// Reject explicit dot-dot traversal segments before cleaning to prevent escaping intended directories.
	normalized := strings.ReplaceAll(trimmed, `\`, "/")
	for _, seg := range strings.Split(normalized, "/") {
		if seg == ".." {
			return fmt.Errorf("%w: dot-dot segment rejected in %q", ErrProbePathTraversal, ux.SanitizeSingleLine(trimmed))
		}
	}
	return nil
}

func loadCustomProbesFromRoot(root *os.Root, rel string) ([]ProbeDefinition, error) {
	// Lstat every path component inside root to defeat intermediate and leaf symlink traps.
	if err := rejectSymlinkComponents(root, rel); err != nil {
		return nil, err
	}

	fi, err := root.Lstat(rel)
	if err != nil {
		return nil, fmt.Errorf("stat probes file %q: %w", rel, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: %q", ErrProbeSymlink, rel)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %q is not a regular file", ErrInvalidProbePack, rel)
	}
	if fi.Size() > MaxCustomProbeFileBytes {
		return nil, fmt.Errorf("%w: file size %d bytes exceeds %d bytes", ErrProbeFileTooLarge, fi.Size(), MaxCustomProbeFileBytes)
	}

	f, err := root.Open(rel)
	if err != nil {
		return nil, fmt.Errorf("open probes file %q: %w", rel, err)
	}
	defer f.Close()

	// Enforce hard 256KB LimitReader cap to defend against TOCTOU file growth after Lstat.
	raw, err := io.ReadAll(io.LimitReader(f, MaxCustomProbeFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read probes file %q: %w", rel, err)
	}
	if len(raw) > MaxCustomProbeFileBytes {
		return nil, fmt.Errorf("%w: read exceeded %d bytes", ErrProbeFileTooLarge, MaxCustomProbeFileBytes)
	}

	return ParseCustomProbesJSON(raw)
}

func rejectSymlinkComponents(root *os.Root, rel string) error {
	clean := filepath.Clean(rel)
	if filepath.IsAbs(clean) || strings.HasPrefix(clean, "..") {
		return fmt.Errorf("%w: %q escapes root", ErrProbePathTraversal, rel)
	}
	parts := strings.Split(clean, string(filepath.Separator))
	var cur string
	for _, p := range parts {
		if p == "" || p == "." {
			continue
		}
		if cur == "" {
			cur = p
		} else {
			cur = filepath.Join(cur, p)
		}
		fi, err := root.Lstat(cur)
		if err != nil {
			return fmt.Errorf("lstat %q: %w", cur, err)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: symlink component %q rejected", ErrProbeSymlink, cur)
		}
	}
	return nil
}

// ParseCustomProbesJSON strictly parses and sanitizes a JSON probe pack (array, {"probes":[...]},
// or a single coppermind distill CustomProbeStub object).
func ParseCustomProbesJSON(raw []byte) ([]ProbeDefinition, error) {
	if len(raw) > MaxCustomProbeFileBytes {
		return nil, fmt.Errorf("%w: payload size %d exceeds %d bytes", ErrProbeFileTooLarge, len(raw), MaxCustomProbeFileBytes)
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("%w: empty probe pack", ErrInvalidProbePack)
	}

	var stubs []CustomProbeStub

	switch trimmed[0] {
	case '[':
		if err := decodeStrictJSON(trimmed, &stubs); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidProbePack, err)
		}
	case '{':
		// Distinguish wrapper envelope {"probes": [...]} from a single coppermind distill stub object.
		var rawMap map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &rawMap); err != nil {
			return nil, fmt.Errorf("%w: malformed JSON object: %v", ErrInvalidProbePack, err)
		}
		if _, hasProbes := rawMap["probes"]; hasProbes {
			var pack CustomProbePack
			if err := decodeStrictJSON(trimmed, &pack); err != nil {
				return nil, fmt.Errorf("%w: %v", ErrInvalidProbePack, err)
			}
			stubs = pack.Probes
		} else {
			var single CustomProbeStub
			if err := decodeStrictJSON(trimmed, &single); err != nil {
				return nil, fmt.Errorf("%w: %v", ErrInvalidProbePack, err)
			}
			stubs = []CustomProbeStub{single}
		}
	default:
		return nil, fmt.Errorf("%w: expected JSON array or object", ErrInvalidProbePack)
	}

	if len(stubs) == 0 {
		return nil, fmt.Errorf("%w: probe pack contains zero probes", ErrInvalidProbePack)
	}
	if len(stubs) > MaxCustomProbes {
		return nil, fmt.Errorf("%w: got %d probes (max %d)", ErrTooManyCustomProbes, len(stubs), MaxCustomProbes)
	}

	defs := make([]ProbeDefinition, 0, len(stubs))
	seenIDs := make(map[string]bool, len(stubs))

	for i, s := range stubs {
		def, err := buildCustomProbeDefinition(s, i)
		if err != nil {
			return nil, err
		}
		if seenIDs[def.ID] {
			return nil, fmt.Errorf("%w: duplicate probe_id %q", ErrInvalidProbePack, def.ID)
		}
		seenIDs[def.ID] = true
		defs = append(defs, def)
	}

	return defs, nil
}

func decodeStrictJSON(raw []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("unexpected trailing tokens after JSON document")
	}
	return nil
}

func buildCustomProbeDefinition(stub CustomProbeStub, idx int) (ProbeDefinition, error) {
	id := ux.SanitizeSingleLine(stub.ProbeID)
	if id == "" {
		return ProbeDefinition{}, fmt.Errorf("%w: probe[%d] missing probe_id", ErrInvalidProbePack, idx)
	}
	if len(id) > maxProbeIDLen {
		id = id[:maxProbeIDLen]
	}

	cat := ProbeCategory(ux.SanitizeSingleLine(string(stub.Category)))
	if !IsValidProbeCategory(cat) {
		return ProbeDefinition{}, fmt.Errorf("%w: probe %q has unknown category %q", ErrInvalidProbeCategory, id, cat)
	}

	payload := strings.TrimSpace(ux.SanitizeTerminalText(stub.Payload))
	if payload == "" {
		return ProbeDefinition{}, fmt.Errorf("%w: probe %q missing payload", ErrInvalidProbePack, id)
	}

	expectedSignal := ux.SanitizeSingleLine(stub.ExpectedSignal)
	if expectedSignal == "" {
		return ProbeDefinition{}, fmt.Errorf("%w: probe %q missing expected_signal", ErrInvalidProbePack, id)
	}

	name := ux.SanitizeSingleLine(stub.Name)
	if name == "" {
		name = id
	}

	summary := ux.SanitizeSingleLine(stub.Summary)
	if summary == "" {
		summary = fmt.Sprintf("custom probe %s matched exploit signal %q", id, expectedSignal)
	}

	fixHint := strings.TrimSpace(ux.SanitizeTerminalText(stub.FixPatchHint))
	if fixHint == "" {
		fixHint = "Enforce deterministic input fencing, scope verification, and output redaction outside the LLM loop."
	}

	whyOneLiner := ux.SanitizeSingleLine(stub.WhyOneLiner)
	if whyOneLiner == "" {
		whyOneLiner = "Regression probe distilled from a prior security lesson caught a reachable boundary bypass."
	}

	deepWhy := strings.TrimSpace(ux.SanitizeTerminalText(stub.DeepWhy))
	tool := ux.SanitizeSingleLine(stub.Tool)
	tenantID := ux.SanitizeSingleLine(stub.TenantID)
	doc := strings.TrimSpace(ux.SanitizeTerminalText(stub.Document))
	if doc == "" {
		doc = payload
	}

	cleanArgs := sanitizeProbeArgs(stub.Args)
	if len(cleanArgs) == 0 {
		cleanArgs = map[string]any{"payload": payload}
	}

	req := ProbeRequest{
		ProbeID:  id,
		Category: cat,
		Prompt:   payload,
		Document: doc,
		TenantID: tenantID,
		Tool:     tool,
		Args:     cleanArgs,
	}

	expectedLower := strings.ToLower(expectedSignal)

	return ProbeDefinition{
		ID:             id,
		Category:       cat,
		Name:           name,
		Summary:        summary,
		OffendingInput: payload,
		FixPatchHint:   fixHint,
		WhyOneLiner:    whyOneLiner,
		DeepWhy:        deepWhy,
		Request:        req,
		VerifyProof: func(respBody string, statusCode int) (bool, string) {
			cleanBody := StripANSI(respBody)
			if isExplicitRefusal(cleanBody, statusCode) {
				return false, ""
			}
			if strings.Contains(strings.ToLower(cleanBody), expectedLower) {
				return true, fmt.Sprintf("Custom probe %s observed expected exploit signal %q in target response", id, expectedSignal)
			}
			return false, ""
		},
	}, nil
}

func sanitizeProbeArgs(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		cleanKey := ux.SanitizeSingleLine(k)
		if cleanKey == "" {
			continue
		}
		out[cleanKey] = sanitizeProbeValue(v, 0)
	}
	return out
}

func sanitizeProbeValue(v any, depth int) any {
	if depth > 8 {
		return ""
	}
	switch typed := v.(type) {
	case string:
		return ux.SanitizeTerminalText(typed)
	case []any:
		res := make([]any, len(typed))
		for i, elem := range typed {
			res[i] = sanitizeProbeValue(elem, depth+1)
		}
		return res
	case map[string]any:
		res := make(map[string]any, len(typed))
		for k, elem := range typed {
			cleanKey := ux.SanitizeSingleLine(k)
			if cleanKey != "" {
				res[cleanKey] = sanitizeProbeValue(elem, depth+1)
			}
		}
		return res
	default:
		return typed
	}
}
