package mcp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/bonjoski/aegisbox/pkg/ux"
	"github.com/bonjoski/aegisbox/pkg/version"
)

// BLPR-v1 constants conforming to blpr-v1.schema.json.
const (
	StatementTypeV1    = "https://in-toto.io/Statement/v1"
	PredicateTypeV1    = "https://bonjoski.dev/attestation/paved-road/v1"
	DSSEPayloadType    = "application/vnd.in-toto+json"
	BLPRSchemaVersion  = "1.0.0"
	BLPRProducerTool   = "aegisbox"
	BLPRProducerStage  = "testing_validation"
	UBMCPSchemaVersion = "ub-cli-v2"
)

// Deterministic UB-CLI-v2 / UB-MCP-v1 ecosystem exit codes.
const (
	ExitOK                = 0
	ExitRuntimeErr        = 1
	ExitPolicyDeny        = 10
	ExitSupplyChainBlock  = 20
	ExitSandboxViolation  = 30
	ExitSecretGuardBlock  = 40
	ExitBiometricRequired = 82
)

var (
	// ErrSymlinkReceiptDir indicates FABRIAL_RECEIPT_DIR or an ancestor resolves through a symlink.
	ErrSymlinkReceiptDir = errors.New("refusing symlinked receipt directory")

	sessionIDRe = regexp.MustCompile(`^sess_[0-9A-Za-z]+$`)
	receiptIDRe = regexp.MustCompile(`^rcpt_[0-9A-Za-z]+$`)
	gitSHARe    = regexp.MustCompile(`^[a-f0-9]{7,64}$`)
	codeRe      = regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,63}$`)
	toolNameRe  = regexp.MustCompile(`^[a-z][a-z0-9_]{2,63}$`)
)

// SelfHealSuggestion carries allowlisted structured remediation guidance for MCP agents.
type SelfHealSuggestion struct {
	SuggestedTool         string                 `json:"suggested_tool"`
	SuggestedArgs         map[string]interface{} `json:"suggested_args"`
	RequiresHumanApproval bool                   `json:"requires_human_approval"`
}

// UBMCPError conforms strictly to ub-mcp-v1-error.schema.json.
type UBMCPError struct {
	SchemaVersion  string              `json:"schema_version"`
	Tool           string              `json:"tool"`
	Code           string              `json:"code"`
	ExitCode       int                 `json:"exit_code"`
	Retryable      bool                `json:"retryable"`
	Summary        string              `json:"summary"`
	RemediationCmd string              `json:"remediation_cmd"`
	Why            string              `json:"why"`
	DeepWhy        string              `json:"deep_why,omitempty"`
	SelfHeal       *SelfHealSuggestion `json:"self_heal,omitempty"`
	ReceiptID      string              `json:"receipt_id,omitempty"`
	References     []string            `json:"references,omitempty"`
}

func (e *UBMCPError) Error() string {
	if e == nil {
		return ""
	}
	return ux.SanitizeSingleLine(e.Summary)
}

// Sanitized returns a schema-compliant, ANSI-stripped copy of UBMCPError.
func (e *UBMCPError) Sanitized() *UBMCPError {
	if e == nil {
		return nil
	}
	code := ux.SanitizeSingleLine(strings.ToUpper(e.Code))
	if !codeRe.MatchString(code) {
		code = "AEGISBOX_RUNTIME_ERROR"
	}

	exitCode := e.ExitCode
	switch exitCode {
	case ExitRuntimeErr, ExitPolicyDeny, ExitSupplyChainBlock, ExitSandboxViolation, ExitSecretGuardBlock, ExitBiometricRequired:
	default:
		exitCode = ExitRuntimeErr
	}

	summary := truncateUTF8(ux.SanitizeSingleLine(e.Summary), 240)
	if summary == "" {
		summary = "Aegisbox paused execution due to a security or runtime constraint."
	}
	remediation := truncateUTF8(ux.SanitizeSingleLine(e.RemediationCmd), 256)
	if remediation == "" {
		remediation = "aegisbox explain microvm"
	}
	why := truncateUTF8(ux.SanitizeSingleLine(e.Why), 280)
	if why == "" {
		why = "Aegisbox fails closed when a security invariant or isolation prerequisite is not satisfied."
	}

	out := &UBMCPError{
		SchemaVersion:  UBMCPSchemaVersion,
		Tool:           BLPRProducerTool,
		Code:           code,
		ExitCode:       exitCode,
		Retryable:      e.Retryable,
		Summary:        summary,
		RemediationCmd: remediation,
		Why:            why,
		DeepWhy:        truncateUTF8(strings.TrimSpace(ux.SanitizeTerminalText(e.DeepWhy)), 2048),
	}

	if rcpt := ux.SanitizeSingleLine(e.ReceiptID); receiptIDRe.MatchString(rcpt) {
		out.ReceiptID = rcpt
	}

	if e.SelfHeal != nil {
		tool := ux.SanitizeSingleLine(e.SelfHeal.SuggestedTool)
		if toolNameRe.MatchString(tool) {
			args := e.SelfHeal.SuggestedArgs
			if args == nil {
				args = map[string]interface{}{}
			}
			out.SelfHeal = &SelfHealSuggestion{
				SuggestedTool:         tool,
				SuggestedArgs:         sanitizeSelfHealArgs(args),
				RequiresHumanApproval: e.SelfHeal.RequiresHumanApproval,
			}
		}
	}

	if len(e.References) > 0 {
		for _, ref := range e.References {
			clean := ux.SanitizeSingleLine(ref)
			if strings.HasPrefix(clean, "https://") || strings.HasPrefix(clean, "http://") {
				out.References = append(out.References, clean)
			}
		}
	}

	return out
}

// HumanText renders a calm, ANSI-stripped <=3-line human message for MCP content[0].text.
func (e *UBMCPError) HumanText() string {
	clean := e.Sanitized()
	if clean == nil {
		return ""
	}
	ff := &ux.FixForwardError{
		Tool:           clean.Tool,
		Code:           clean.Code,
		Summary:        clean.Summary,
		RemediationCmd: clean.RemediationCmd,
		WhyOneLiner:    clean.Why,
		ExitCode:       clean.ExitCode,
	}
	var buf bytes.Buffer
	_ = ff.Render(&buf, false, false)
	return strings.TrimRight(buf.String(), "\n")
}

// ToolContent represents a single MCP CallToolResult content item.
type ToolContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// CallToolResult is the UB-MCP-v1 harmonized MCP tool call result payload.
type CallToolResult struct {
	Content           []ToolContent `json:"content"`
	StructuredContent interface{}   `json:"structuredContent,omitempty"`
	IsError           bool          `json:"isError"`
}

// NewErrorCallToolResult converts any error into a schema-valid UB-MCP-v1 CallToolResult.
func NewErrorCallToolResult(err error) CallToolResult {
	var ubErr *UBMCPError
	if !errors.As(err, &ubErr) || ubErr == nil {
		msg := ""
		if err != nil {
			msg = err.Error()
		}
		ubErr = &UBMCPError{
			SchemaVersion:  UBMCPSchemaVersion,
			Tool:           BLPRProducerTool,
			Code:           "AEGISBOX_RUNTIME_ERROR",
			ExitCode:       ExitRuntimeErr,
			Retryable:      false,
			Summary:        msg,
			RemediationCmd: "aegisbox doctor",
			Why:            "Inspect the error summary and verify local Aegisbox prerequisites before retrying.",
		}
	}
	sanitized := ubErr.Sanitized()
	return CallToolResult{
		Content: []ToolContent{
			{
				Type: "text",
				Text: sanitized.HumanText(),
			},
		},
		StructuredContent: sanitized,
		IsError:           true,
	}
}

// ReceiptVerdict represents a BLPR-v1 receipt verdict.
type ReceiptVerdict string

const (
	ReceiptVerdictAllow ReceiptVerdict = "allow"
	ReceiptVerdictDeny  ReceiptVerdict = "deny"
	ReceiptVerdictWarn  ReceiptVerdict = "warn"
)

// ReceiptSubject represents an in-toto Statement v1 subject entry.
type ReceiptSubject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// ReceiptSession captures BLPR-v1 session lineage.
type ReceiptSession struct {
	SessionID       string `json:"session_id"`
	ParentSessionID string `json:"parent_session_id,omitempty"`
	ActorMode       string `json:"actor_mode"`
	WorktreeHeadSHA string `json:"worktree_head_sha"`
}

// ReceiptProducer identifies the local tool producing the BLPR-v1 receipt.
type ReceiptProducer struct {
	Tool    string `json:"tool"`
	Version string `json:"version"`
	Stage   string `json:"stage"`
}

// ReceiptPredicate conforms to blpr-v1.schema.json predicate definition.
type ReceiptPredicate struct {
	SchemaVersion  string          `json:"schema_version"`
	ReceiptID      string          `json:"receipt_id"`
	Timestamp      time.Time       `json:"timestamp"`
	Session        ReceiptSession  `json:"session"`
	Producer       ReceiptProducer `json:"producer"`
	Verdict        ReceiptVerdict  `json:"verdict"`
	Proven         bool            `json:"proven"`
	Claims         json.RawMessage `json:"claims"`
	ParentReceipts []string        `json:"parent_receipts,omitempty"`
	FixForwardCode string          `json:"fix_forward_code,omitempty"`
}

// InTotoStatement represents an in-toto Statement v1 carrying a BLPR-v1 predicate.
type InTotoStatement struct {
	Type          string           `json:"_type"`
	Subject       []ReceiptSubject `json:"subject"`
	PredicateType string           `json:"predicateType"`
	Predicate     ReceiptPredicate `json:"predicate"`
}

// DSSESignature is a single signature entry in a DSSE envelope.
type DSSESignature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// DSSEEnvelope is the top-level BLPR-v1 signed receipt container.
type DSSEEnvelope struct {
	PayloadType string          `json:"payloadType"`
	Payload     string          `json:"payload"`
	Signatures  []DSSESignature `json:"signatures"`
}

// ReceiptSigner abstracts Locksmith UDS DSSE signing for BLPR-v1 receipts.
type ReceiptSigner interface {
	SignDSSE(ctx context.Context, sessionID string, pae []byte) (keyID string, sig []byte, err error)
}

// PAE computes the DSSE v1 Pre-Authentication Encoding:
// "DSSEv1 " + len(type) + " " + type + " " + len(body) + " " + body
func PAE(payloadType string, payload []byte) []byte {
	prefix := fmt.Sprintf("DSSEv1 %d %s %d ", len(payloadType), payloadType, len(payload))
	out := make([]byte, 0, len(prefix)+len(payload))
	out = append(out, prefix...)
	out = append(out, payload...)
	return out
}

// VerifyReceiptEnvelope verifies a BLPR-v1 DSSE envelope signature and decodes its Statement.
func VerifyReceiptEnvelope(env *DSSEEnvelope, pub ed25519.PublicKey) (*InTotoStatement, error) {
	if env == nil || env.PayloadType != DSSEPayloadType || len(env.Signatures) == 0 {
		return nil, errors.New("invalid or unsigned DSSE receipt envelope")
	}
	raw, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("decode DSSE payload: %w", err)
	}
	pae := PAE(env.PayloadType, raw)
	verified := false
	for _, s := range env.Signatures {
		sigBytes, decErr := base64.StdEncoding.DecodeString(s.Sig)
		if decErr != nil || len(sigBytes) != ed25519.SignatureSize {
			continue
		}
		if ed25519.Verify(pub, pae, sigBytes) {
			verified = true
			break
		}
	}
	if !verified {
		return nil, errors.New("DSSE Ed25519 signature verification failed")
	}
	var stmt InTotoStatement
	if err := json.Unmarshal(raw, &stmt); err != nil {
		return nil, fmt.Errorf("unmarshal in-toto statement: %w", err)
	}
	if stmt.Type != StatementTypeV1 || stmt.PredicateType != PredicateTypeV1 {
		return nil, errors.New("unexpected in-toto statement or predicate type")
	}
	if !receiptIDRe.MatchString(stmt.Predicate.ReceiptID) || !sessionIDRe.MatchString(stmt.Predicate.Session.SessionID) {
		return nil, errors.New("invalid receipt_id or session_id format in statement")
	}
	return &stmt, nil
}

// ReceiptParams carries inputs for emitting a signed BLPR-v1 receipt.
type ReceiptParams struct {
	ReceiptDir     string
	SessionID      string
	WorkspaceDir   string
	SubjectName    string
	SubjectDigest  string
	Verdict        ReceiptVerdict
	Proven         bool
	Claims         map[string]interface{}
	FixForwardCode string
	Signer         ReceiptSigner
	ExplicitEmit   bool
}

// EmitBLPRReceipt builds, signs via Locksmith UDS, and atomically writes a BLPR-v1 receipt.
// Returns (receiptID, filePath, error). When receiptDir is empty and ExplicitEmit is false, returns ("", "", nil).
func EmitBLPRReceipt(ctx context.Context, p ReceiptParams) (string, string, error) {
	receiptDir := strings.TrimSpace(p.ReceiptDir)
	if receiptDir == "" {
		receiptDir = strings.TrimSpace(os.Getenv("FABRIAL_RECEIPT_DIR"))
	}
	if receiptDir == "" {
		if p.ExplicitEmit {
			return "", "", &UBMCPError{
				SchemaVersion:  UBMCPSchemaVersion,
				Tool:           BLPRProducerTool,
				Code:           "AEGISBOX_RECEIPT_DIR_UNSET",
				ExitCode:       ExitPolicyDeny,
				Retryable:      true,
				Summary:        "Receipt emission was requested, but FABRIAL_RECEIPT_DIR is not set.",
				RemediationCmd: `eval "$(fabrial session begin)"`,
				Why:            "BLPR-v1 receipts are persisted inside the active local Fabrial session directory.",
			}
		}
		return "", "", nil
	}

	// Security invariant: ALWAYS reject symlinked receipt directories BEFORE dialing Locksmith or writing anything.
	if err := validateReceiptDirNoSymlink(receiptDir); err != nil {
		return "", "", &UBMCPError{
			SchemaVersion:  UBMCPSchemaVersion,
			Tool:           BLPRProducerTool,
			Code:           "AEGISBOX_RECEIPT_SYMLINK_BLOCKED",
			ExitCode:       ExitPolicyDeny,
			Retryable:      false,
			Summary:        "Refused to write BLPR-v1 receipt because FABRIAL_RECEIPT_DIR resolves through a symlink.",
			RemediationCmd: `eval "$(fabrial session begin)"`,
			Why:            "Receipt directories must be real local directories opened with O_NOFOLLOW to prevent symlink traversal attacks.",
		}
	}

	sessionID := normalizeSessionID(p.SessionID)
	receiptID := generateReceiptID()

	headSHA := resolveWorktreeHeadSHA(p.WorkspaceDir)
	subjectName := strings.TrimSpace(p.SubjectName)
	if subjectName == "" {
		subjectName = "aegisbox-session"
	}
	if len(subjectName) > 512 {
		subjectName = subjectName[:512]
	}

	digest := strings.ToLower(strings.TrimSpace(p.SubjectDigest))
	if len(digest) != 64 || !gitSHARe.MatchString(digest) {
		sum := sha256.Sum256([]byte(subjectName + ":" + headSHA))
		digest = hex.EncodeToString(sum[:])
	}

	claimsMap := p.Claims
	if claimsMap == nil {
		claimsMap = map[string]interface{}{}
	}
	claimsJSON, err := json.Marshal(claimsMap)
	if err != nil {
		return "", "", fmt.Errorf("marshal BLPR-v1 claims: %w", err)
	}

	fixCode := ux.SanitizeSingleLine(strings.ToUpper(p.FixForwardCode))
	if fixCode != "" && !codeRe.MatchString(fixCode) {
		fixCode = ""
	}

	ver := strings.TrimSpace(version.Version)
	if ver == "" {
		ver = "0.8.0"
	}

	stmt := InTotoStatement{
		Type: StatementTypeV1,
		Subject: []ReceiptSubject{
			{
				Name:   subjectName,
				Digest: map[string]string{"sha256": digest},
			},
		},
		PredicateType: PredicateTypeV1,
		Predicate: ReceiptPredicate{
			SchemaVersion: BLPRSchemaVersion,
			ReceiptID:     receiptID,
			Timestamp:     time.Now().UTC(),
			Session: ReceiptSession{
				SessionID:       sessionID,
				ActorMode:       "aidlc",
				WorktreeHeadSHA: headSHA,
			},
			Producer: ReceiptProducer{
				Tool:    BLPRProducerTool,
				Version: ver,
				Stage:   BLPRProducerStage,
			},
			Verdict:        p.Verdict,
			Proven:         p.Proven,
			Claims:         claimsJSON,
			FixForwardCode: fixCode,
		},
	}

	payloadBytes, err := json.Marshal(stmt)
	if err != nil {
		return "", "", fmt.Errorf("marshal BLPR-v1 statement: %w", err)
	}

	signer := p.Signer
	if signer == nil {
		broker, bErr := NewLocksmithBroker()
		if bErr == nil {
			signer = broker
		}
	}
	if signer == nil {
		if p.ExplicitEmit {
			return "", "", &UBMCPError{
				SchemaVersion:  UBMCPSchemaVersion,
				Tool:           BLPRProducerTool,
				Code:           "AEGISBOX_RECEIPT_SIGN_FAILED",
				ExitCode:       ExitBiometricRequired,
				Retryable:      true,
				Summary:        "Locksmith UDS signer is unavailable for BLPR-v1 receipt signing.",
				RemediationCmd: `eval "$(fabrial session begin)"`,
				Why:            "Signed local receipts require an active Locksmith session daemon over LOCKSMITH_SOCKET.",
			}
		}
		return "", "", nil
	}

	pae := PAE(DSSEPayloadType, payloadBytes)
	keyID, sigBytes, signErr := signer.SignDSSE(ctx, sessionID, pae)
	if signErr != nil {
		if p.ExplicitEmit {
			exitCode := ExitPolicyDeny
			code := "AEGISBOX_RECEIPT_SIGN_FAILED"
			if errors.Is(signErr, ErrBiometricDenied) {
				exitCode = ExitBiometricRequired
				code = "AEGISBOX_BIOMETRIC_REQUIRED"
			}
			return "", "", &UBMCPError{
				SchemaVersion:  UBMCPSchemaVersion,
				Tool:           BLPRProducerTool,
				Code:           code,
				ExitCode:       exitCode,
				Retryable:      true,
				Summary:        fmt.Sprintf("Failed to sign BLPR-v1 receipt via Locksmith UDS: %v", signErr),
				RemediationCmd: `eval "$(fabrial session begin)"`,
				Why:            "BLPR-v1 receipts fail closed unless signed by Locksmith's amortized session Ed25519 key.",
			}
		}
		// Ambient FABRIAL_RECEIPT_DIR without explicit emit_receipt: if Locksmith is unreachable, do not fail unrelated runs.
		return "", "", nil
	}

	if !strings.HasPrefix(keyID, "spiffe://bonjoski.local/session/sess_") {
		keyID = "spiffe://bonjoski.local/session/" + sessionID
	}

	env := &DSSEEnvelope{
		PayloadType: DSSEPayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payloadBytes),
		Signatures: []DSSESignature{
			{
				KeyID: keyID,
				Sig:   base64.StdEncoding.EncodeToString(sigBytes),
			},
		},
	}

	outPath, err := WriteReceiptAtomic(receiptDir, env, receiptID)
	if err != nil {
		if errors.Is(err, ErrSymlinkReceiptDir) {
			return "", "", &UBMCPError{
				SchemaVersion:  UBMCPSchemaVersion,
				Tool:           BLPRProducerTool,
				Code:           "AEGISBOX_RECEIPT_SYMLINK_BLOCKED",
				ExitCode:       ExitPolicyDeny,
				Retryable:      false,
				Summary:        "Refused to write BLPR-v1 receipt because FABRIAL_RECEIPT_DIR resolves through a symlink.",
				RemediationCmd: `eval "$(fabrial session begin)"`,
				Why:            "Receipt directories must be real local directories opened with O_NOFOLLOW to prevent symlink traversal attacks.",
			}
		}
		return "", "", err
	}

	return receiptID, outPath, nil
}

// WriteReceiptAtomic validates receiptDir against symlinks, opens it via os.OpenRoot,
// creates a mode 0600 temp file with O_CREAT|O_EXCL, fsyncs, and atomically renames it.
func WriteReceiptAtomic(receiptDir string, env *DSSEEnvelope, receiptID string) (string, error) {
	if err := validateReceiptDirNoSymlink(receiptDir); err != nil {
		return "", err
	}

	if err := os.MkdirAll(receiptDir, 0o700); err != nil {
		return "", fmt.Errorf("create receipt dir: %w", err)
	}

	// Re-check after MkdirAll to close any TOCTOU window on the leaf directory.
	if err := validateReceiptDirNoSymlink(receiptDir); err != nil {
		return "", err
	}

	root, err := os.OpenRoot(receiptDir)
	if err != nil {
		return "", fmt.Errorf("open receipt root: %w", err)
	}
	defer root.Close()

	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal DSSE envelope: %w", err)
	}
	data = append(data, '\n')

	suffix := strings.TrimPrefix(receiptID, "rcpt_")
	if suffix == "" {
		suffix = randomAlphaNum(16)
	}
	finalName := fmt.Sprintf("%d-%s-%s.dsse.json", time.Now().UTC().UnixMilli(), BLPRProducerTool, suffix)
	tmpName := fmt.Sprintf(".tmp-%s-%s", suffix, randomAlphaNum(8))

	f, err := root.OpenFile(tmpName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("create atomic receipt temp file: %w", err)
	}

	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = root.Remove(tmpName)
		return "", fmt.Errorf("write receipt temp file: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = root.Remove(tmpName)
		return "", fmt.Errorf("fsync receipt temp file: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = root.Remove(tmpName)
		return "", fmt.Errorf("close receipt temp file: %w", err)
	}

	if err := root.Rename(tmpName, finalName); err != nil {
		_ = root.Remove(tmpName)
		return "", fmt.Errorf("atomic rename receipt: %w", err)
	}

	return filepath.Join(receiptDir, finalName), nil
}

// validateReceiptDirNoSymlink ensures neither receiptDir nor any non-system ancestor is a symlink.
func validateReceiptDirNoSymlink(receiptDir string) error {
	if strings.TrimSpace(receiptDir) == "" || strings.ContainsRune(receiptDir, '\x00') {
		return fmt.Errorf("%w: empty or invalid path", ErrSymlinkReceiptDir)
	}
	clean := filepath.Clean(receiptDir)

	// Walk every existing component from clean upward, rejecting any symlink
	// (while exempting macOS well-known top-level OS symlinks /var, /tmp, /etc -> /private/*).
	cur := clean
	for {
		if isDarwinSystemSymlinkRoot(cur) {
			break
		}
		fi, err := os.Lstat(cur)
		if err == nil {
			if fi.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("%w: %s is a symlink", ErrSymlinkReceiptDir, cur)
			}
			if !fi.IsDir() {
				return fmt.Errorf("%w: %s is not a directory", ErrSymlinkReceiptDir, cur)
			}
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("%w: stat %s: %v", ErrSymlinkReceiptDir, cur, err)
		}

		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}
	return nil
}

func isDarwinSystemSymlinkRoot(p string) bool {
	if runtime.GOOS != "darwin" {
		return false
	}
	switch p {
	case "/var", "/tmp", "/etc":
		return true
	default:
		return false
	}
}

func normalizeSessionID(sessionID string) string {
	candidates := []string{
		strings.TrimSpace(sessionID),
		strings.TrimSpace(os.Getenv("FABRIAL_SESSION_ID")),
	}
	for _, c := range candidates {
		if sessionIDRe.MatchString(c) {
			return c
		}
	}
	return "sess_" + randomAlphaNum(20)
}

func generateReceiptID() string {
	return "rcpt_" + randomAlphaNum(20)
}

func randomAlphaNum(n int) string {
	b := make([]byte, (n+1)/2)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%016X", time.Now().UTC().UnixNano())
	}
	s := strings.ToUpper(hex.EncodeToString(b))
	if len(s) > n {
		return s[:n]
	}
	return s
}

// resolveWorktreeHeadSHA reads .git/HEAD without spawning any subprocesses.
func resolveWorktreeHeadSHA(dir string) string {
	const fallback = "0000000000000000000000000000000000000000"
	if dir == "" {
		var err error
		dir, err = os.Getwd()
		if err != nil {
			return fallback
		}
	}
	cur := filepath.Clean(dir)
	for {
		gitPath := filepath.Join(cur, ".git")
		fi, err := os.Stat(gitPath)
		if err == nil {
			gitDir := gitPath
			if !fi.IsDir() {
				// Worktree .git file: "gitdir: /path/to/gitdir"
				raw, rErr := os.ReadFile(gitPath)
				if rErr == nil {
					line := strings.TrimSpace(string(raw))
					if strings.HasPrefix(line, "gitdir:") {
						target := strings.TrimSpace(strings.TrimPrefix(line, "gitdir:"))
						if !filepath.IsAbs(target) {
							target = filepath.Join(cur, target)
						}
						gitDir = filepath.Clean(target)
					}
				}
			}
			if sha := readGitHeadSHA(gitDir); sha != "" {
				return sha
			}
			break
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}
	return fallback
}

func readGitHeadSHA(gitDir string) string {
	raw, err := os.ReadFile(filepath.Join(gitDir, "HEAD"))
	if err != nil {
		return ""
	}
	head := strings.TrimSpace(string(raw))
	if gitSHARe.MatchString(head) {
		return head
	}
	if strings.HasPrefix(head, "ref:") {
		ref := strings.TrimSpace(strings.TrimPrefix(head, "ref:"))
		if refRaw, rErr := os.ReadFile(filepath.Join(gitDir, filepath.FromSlash(ref))); rErr == nil {
			sha := strings.TrimSpace(string(refRaw))
			if gitSHARe.MatchString(sha) {
				return sha
			}
		}
		// Check commondir for linked worktrees
		if commonRaw, cErr := os.ReadFile(filepath.Join(gitDir, "commondir")); cErr == nil {
			commonDir := strings.TrimSpace(string(commonRaw))
			if !filepath.IsAbs(commonDir) {
				commonDir = filepath.Join(gitDir, commonDir)
			}
			if refRaw, rErr := os.ReadFile(filepath.Join(commonDir, filepath.FromSlash(ref))); rErr == nil {
				sha := strings.TrimSpace(string(refRaw))
				if gitSHARe.MatchString(sha) {
					return sha
				}
			}
		}
	}
	return ""
}

func sanitizeSelfHealArgs(args map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(args))
	for k, v := range args {
		cleanKey := ux.SanitizeSingleLine(k)
		if cleanKey == "" {
			continue
		}
		switch val := v.(type) {
		case string:
			out[cleanKey] = ux.SanitizeSingleLine(val)
		case []string:
			arr := make([]string, 0, len(val))
			for _, item := range val {
				arr = append(arr, ux.SanitizeSingleLine(item))
			}
			out[cleanKey] = arr
		default:
			out[cleanKey] = v
		}
	}
	return out
}

func truncateUTF8(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	runes := []rune(s)
	var b strings.Builder
	for _, r := range runes {
		if b.Len()+len(string(r)) > maxLen {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}
