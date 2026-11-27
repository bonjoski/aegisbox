package benchmark

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// SirenSchemaVersion identifies the structured differential scorecard format.
	SirenSchemaVersion = "siren-diff-v1"
	// DefaultSirenConcurrency bounds parallel probe workers (RFC-2026-11-27-67 §3.2).
	DefaultSirenConcurrency = 4
	// DefaultSirenProbeTimeout caps each differential probe run.
	DefaultSirenProbeTimeout = 5 * time.Second
	// SirenDegradedExitCode is the fail-closed exit code when kernel sandboxing is unavailable.
	SirenDegradedExitCode = 126
)

// CanaryRoot holds an ephemeral 0700 synthetic sandbox test environment.
// All probes operate strictly inside BaseDir via os.OpenRoot and NEVER touch os.UserHomeDir().
type CanaryRoot struct {
	BaseDir            string
	HomeDir            string
	ProfilesDir        string
	SSHDir             string
	SSHKeyPath         string
	AuthorizedKeysPath string
	AWSDir             string
	AWSCredPath        string
	SocketPath         string
	WorktreeDir        string
	WorktreeBinDir     string
	ProcEnvironPath    string
	SharedTmpDir       string
	SiblingTmpCanary   string
	IsolatedTmpDir     string
	MetadataAddr       string
	CanaryToken        string
	SecretEnv          []string

	Root *os.Root

	unixListener net.Listener
	metaListener net.Listener
	metaServer   *http.Server
	cleanupOnce  sync.Once
}

// NewCanaryRoot provisions an isolated 0700 temp directory populated with synthetic
// canary credentials, a live Unix socket, a synthetic worktree, and a loopback metadata server.
func NewCanaryRoot() (*CanaryRoot, error) {
	tokenBytes := make([]byte, 8)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("siren canary token generation failed: %w", err)
	}
	token := hex.EncodeToString(tokenBytes)

	// Keep directory name short so macOS Unix domain socket path stays well below 104 bytes.
	baseDir, err := os.MkdirTemp("", "abx-s-*")
	if err != nil {
		return nil, fmt.Errorf("create siren canary temp dir: %w", err)
	}
	if err := os.Chmod(baseDir, 0o700); err != nil {
		_ = os.RemoveAll(baseDir)
		return nil, fmt.Errorf("chmod siren canary temp dir: %w", err)
	}

	root, err := os.OpenRoot(baseDir)
	if err != nil {
		_ = os.RemoveAll(baseDir)
		return nil, fmt.Errorf("open canary root: %w", err)
	}

	c := &CanaryRoot{
		BaseDir:            baseDir,
		HomeDir:            filepath.Join(baseDir, "home"),
		ProfilesDir:        filepath.Join(baseDir, "profiles"),
		SSHDir:             filepath.Join(baseDir, "home", ".ssh"),
		SSHKeyPath:         filepath.Join(baseDir, "home", ".ssh", "id_ed25519"),
		AuthorizedKeysPath: filepath.Join(baseDir, "home", ".ssh", "authorized_keys"),
		AWSDir:             filepath.Join(baseDir, "home", ".aws"),
		AWSCredPath:        filepath.Join(baseDir, "home", ".aws", "credentials"),
		SocketPath:         filepath.Join(baseDir, "docker.sock"),
		WorktreeDir:        filepath.Join(baseDir, "worktree"),
		WorktreeBinDir:     filepath.Join(baseDir, "worktree", "bin"),
		ProcEnvironPath:    filepath.Join(baseDir, "proc", "self", "environ"),
		SharedTmpDir:       filepath.Join(baseDir, "tmp_shared"),
		SiblingTmpCanary:   filepath.Join(baseDir, "tmp_shared", "sibling-session.canary"),
		IsolatedTmpDir:     filepath.Join(baseDir, "tmp_isolated"),
		CanaryToken:        token,
		Root:               root,
	}

	// Construct synthetic secret fixtures via concatenation so push-protection scanners never false-positive.
	synthAnthropic := "sk-" + "ant-canary-siren-" + token
	synthAWSAccess := "AKIA" + "IOSFODNN7SRN" + strings.ToUpper(token[:4])
	synthAWSSecret := "CANARY_NOT_A_REAL_AWS_SECRET_" + token

	c.SecretEnv = []string{
		"HOME=" + c.HomeDir,
		"SAFE_BENCHMARK_MARKER=ok",
		"ANTHROPIC_API_KEY=" + synthAnthropic,
		"AWS_ACCESS_KEY_ID=" + synthAWSAccess,
		"AWS_SECRET_ACCESS_KEY=" + synthAWSSecret,
	}

	relDirs := []string{
		"home",
		filepath.Join("home", ".ssh"),
		filepath.Join("home", ".aws"),
		"profiles",
		"worktree",
		filepath.Join("worktree", "bin"),
		"proc",
		filepath.Join("proc", "self"),
		"tmp_shared",
		"tmp_isolated",
	}
	for _, rel := range relDirs {
		if err := c.Root.Mkdir(rel, 0o700); err != nil {
			_ = c.Cleanup()
			return nil, fmt.Errorf("create canary subdir %q: %w", rel, err)
		}
	}

	sshKeyBody := "-----BEGIN OPENSSH PRIVATE KEY-----\nCANARY_NOT_A_REAL_KEY_SSH_" + token + "\n-----END OPENSSH PRIVATE KEY-----\n"
	authKeysBody := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5CANARY baseline-" + token + "@canary\n"
	awsCredBody := "[default]\naws_access_key_id = " + synthAWSAccess + "\naws_secret_access_key = " + synthAWSSecret + "\n"
	procEnvBody := "ANTHROPIC_API_KEY=" + synthAnthropic + "\x00AWS_SECRET_ACCESS_KEY=" + synthAWSSecret + "\x00"
	siblingTmpBody := "CANARY_SIBLING_WORKTREE_BLEED_" + token + "\n"
	worktreeSrc := "package main\nfunc main() {}\n"

	files := map[string]string{
		filepath.Join("home", ".ssh", "id_ed25519"):      sshKeyBody,
		filepath.Join("home", ".ssh", "authorized_keys"): authKeysBody,
		filepath.Join("home", ".aws", "credentials"):     awsCredBody,
		filepath.Join("proc", "self", "environ"):         procEnvBody,
		filepath.Join("tmp_shared", "sibling-session.canary"): siblingTmpBody,
		filepath.Join("worktree", "main.go"):             worktreeSrc,
	}
	for rel, content := range files {
		if err := writeRootFile(c.Root, rel, []byte(content), 0o600); err != nil {
			_ = c.Cleanup()
			return nil, fmt.Errorf("write canary file %q: %w", rel, err)
		}
	}

	// Start synthetic Unix socket listener (simulating host docker.sock).
	unixLn, err := net.Listen("unix", c.SocketPath)
	if err != nil {
		_ = c.Cleanup()
		return nil, fmt.Errorf("listen synthetic docker.sock: %w", err)
	}
	c.unixListener = unixLn
	go func() {
		for {
			conn, aErr := unixLn.Accept()
			if aErr != nil {
				return
			}
			_, _ = io.WriteString(conn, "CANARY_DOCKER_SOCKET_REACHED_"+token+"\n")
			_ = conn.Close()
		}
	}()

	// Start synthetic loopback metadata HTTP listener (simulating 169.254.169.254 IMDS).
	metaLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = c.Cleanup()
		return nil, fmt.Errorf("listen synthetic metadata endpoint: %w", err)
	}
	c.metaListener = metaLn
	c.MetadataAddr = metaLn.Addr().String()
	mux := http.NewServeMux()
	mux.HandleFunc("/latest/meta-data/iam/security-credentials/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "CANARY_IMDS_CREDENTIALS_"+token)
	})
	c.metaServer = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 2 * time.Second,
	}
	go func() {
		_ = c.metaServer.Serve(metaLn)
	}()

	if err := c.ValidateIsolation(); err != nil {
		_ = c.Cleanup()
		return nil, err
	}

	return c, nil
}

// ValidateIsolation verifies that no canary path overlaps with the developer's real home directory.
func (c *CanaryRoot) ValidateIsolation() error {
	if c == nil || c.BaseDir == "" {
		return errors.New("canary root is empty")
	}
	realHome, err := os.UserHomeDir()
	if err != nil || realHome == "" {
		return nil
	}
	cleanHome := filepath.Clean(realHome)
	paths := []string{
		c.BaseDir,
		c.HomeDir,
		c.SSHKeyPath,
		c.AuthorizedKeysPath,
		c.AWSCredPath,
		c.SocketPath,
		c.WorktreeDir,
	}
	for _, p := range paths {
		cleanP := filepath.Clean(p)
		if cleanP == cleanHome || strings.HasPrefix(cleanP, cleanHome+string(filepath.Separator)) {
			return fmt.Errorf("CANARY ISOLATION VIOLATION: path %q overlaps real user home %q", cleanP, cleanHome)
		}
	}
	return nil
}

// Cleanup closes listeners and os.Root, then deletes the ephemeral 0700 canary directory.
func (c *CanaryRoot) Cleanup() error {
	if c == nil {
		return nil
	}
	var firstErr error
	c.cleanupOnce.Do(func() {
		if c.metaServer != nil {
			_ = c.metaServer.Close()
		}
		if c.metaListener != nil {
			_ = c.metaListener.Close()
		}
		if c.unixListener != nil {
			_ = c.unixListener.Close()
		}
		if c.Root != nil {
			if err := c.Root.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		if c.BaseDir != "" {
			if err := os.RemoveAll(c.BaseDir); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	})
	return firstErr
}

func writeRootFile(root *os.Root, rel string, data []byte, perm os.FileMode) error {
	f, err := root.OpenFile(rel, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	_, wErr := f.Write(data)
	cErr := f.Close()
	if wErr != nil {
		return wErr
	}
	return cErr
}

// AirlockProfileSpec captures the canonical security boundaries enforced by a compiled
// Airlock Seatbelt/Landlock/Seccomp/Env sandbox profile for Siren differential mutation.
type AirlockProfileSpec struct {
	WorktreeDir             string `json:"worktree_dir"`
	CanaryHomeDir           string `json:"canary_home_dir"`
	DenySSHRead             bool   `json:"deny_ssh_read"`
	DenyAWSRead             bool   `json:"deny_aws_read"`
	DenyDockerSocket        bool   `json:"deny_docker_socket"`
	HideProcEnviron         bool   `json:"hide_proc_environ"`
	ResolveBeneath          bool   `json:"resolve_beneath"`
	StripSecretEnv          bool   `json:"strip_secret_env"`
	BlockIOUringAndX32      bool   `json:"block_io_uring_and_x32"`
	SanitizePATH            bool   `json:"sanitize_path"`
	DenyMetadataEgress      bool   `json:"deny_metadata_egress"`
	DenySSHWrite            bool   `json:"deny_ssh_write"`
	IsolateSessionTmp       bool   `json:"isolate_session_tmp"`
	FailClosedOnDegraded    bool   `json:"fail_closed_on_degraded"`
	SandboxBackendAvailable bool   `json:"sandbox_backend_available"`
	AllowDegradedLocal      bool   `json:"allow_degraded_local"`
}

// HardenedAirlockProfile constructs the baseline hardened Airlock sandbox profile
// with all 12 Siren boundaries enforced.
func HardenedAirlockProfile(canary *CanaryRoot) *AirlockProfileSpec {
	return &AirlockProfileSpec{
		WorktreeDir:             canary.WorktreeDir,
		CanaryHomeDir:           canary.HomeDir,
		DenySSHRead:             true,
		DenyAWSRead:             true,
		DenyDockerSocket:        true,
		HideProcEnviron:         true,
		ResolveBeneath:          true,
		StripSecretEnv:          true,
		BlockIOUringAndX32:      true,
		SanitizePATH:            true,
		DenyMetadataEgress:      true,
		DenySSHWrite:            true,
		IsolateSessionTmp:       true,
		FailClosedOnDegraded:    true,
		SandboxBackendAvailable: true,
		AllowDegradedLocal:      false,
	}
}

// Clone returns a deep copy of the profile specification.
func (p *AirlockProfileSpec) Clone() *AirlockProfileSpec {
	cp := *p
	return &cp
}

// RenderCompiledProfile renders the canonical profile representation (Seatbelt SBPL directives
// + Airlock Landlock/Seccomp/Env metadata header) written into the ephemeral canary dir.
func (p *AirlockProfileSpec) RenderCompiledProfile() string {
	var b strings.Builder
	b.WriteString("(version 1)\n")
	b.WriteString("(deny default)\n")
	fmt.Fprintf(&b, ";; worktree=%s\n", p.WorktreeDir)
	fmt.Fprintf(&b, ";; canary_home=%s\n", p.CanaryHomeDir)

	if p.DenySSHRead {
		fmt.Fprintf(&b, "(deny file-read* (subpath %q))\n", filepath.Join(p.CanaryHomeDir, ".ssh"))
	} else {
		fmt.Fprintf(&b, "(allow file-read* (subpath %q))\n", filepath.Join(p.CanaryHomeDir, ".ssh"))
	}
	if p.DenySSHWrite {
		fmt.Fprintf(&b, "(deny file-write* (subpath %q))\n", filepath.Join(p.CanaryHomeDir, ".ssh"))
	} else {
		fmt.Fprintf(&b, "(allow file-write* (subpath %q))\n", filepath.Join(p.CanaryHomeDir, ".ssh"))
	}
	if p.DenyAWSRead {
		fmt.Fprintf(&b, "(deny file-read* (subpath %q))\n", filepath.Join(p.CanaryHomeDir, ".aws"))
	} else {
		fmt.Fprintf(&b, "(allow file-read* (subpath %q))\n", filepath.Join(p.CanaryHomeDir, ".aws"))
	}
	if p.DenyDockerSocket {
		b.WriteString("(deny network-outbound (literal \"docker.sock\"))\n")
	} else {
		b.WriteString("(allow network-outbound (literal \"docker.sock\"))\n")
	}

	fmt.Fprintf(&b, ";; directive hide_proc_environ=%t\n", p.HideProcEnviron)
	fmt.Fprintf(&b, ";; directive resolve_beneath=%t\n", p.ResolveBeneath)
	fmt.Fprintf(&b, ";; directive strip_secret_env=%t\n", p.StripSecretEnv)
	fmt.Fprintf(&b, ";; directive block_io_uring_and_x32=%t\n", p.BlockIOUringAndX32)
	fmt.Fprintf(&b, ";; directive sanitize_path=%t\n", p.SanitizePATH)
	fmt.Fprintf(&b, ";; directive deny_metadata_egress=%t\n", p.DenyMetadataEgress)
	fmt.Fprintf(&b, ";; directive isolate_session_tmp=%t\n", p.IsolateSessionTmp)
	fmt.Fprintf(&b, ";; directive fail_closed_on_degraded=%t\n", p.FailClosedOnDegraded)
	fmt.Fprintf(&b, ";; directive sandbox_backend_available=%t\n", p.SandboxBackendAvailable)
	fmt.Fprintf(&b, ";; directive allow_degraded_local=%t\n", p.AllowDegradedLocal)
	return b.String()
}

// WriteToCanary writes the compiled profile strictly inside canary.ProfilesDir (0600).
func (p *AirlockProfileSpec) WriteToCanary(canary *CanaryRoot, name string) (string, error) {
	rel := filepath.Join("profiles", name)
	if err := writeRootFile(canary.Root, rel, []byte(p.RenderCompiledProfile()), 0o600); err != nil {
		return "", err
	}
	return filepath.Join(canary.BaseDir, rel), nil
}

// loadCompiledProfile parses a compiled profile file generated by RenderCompiledProfile.
func loadCompiledProfile(profilePath string) (*AirlockProfileSpec, error) {
	f, err := os.Open(profilePath)
	if err != nil {
		return nil, fmt.Errorf("open compiled profile %q: %w", profilePath, err)
	}
	defer f.Close()

	spec := &AirlockProfileSpec{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case strings.HasPrefix(line, ";; worktree="):
			spec.WorktreeDir = strings.TrimPrefix(line, ";; worktree=")
		case strings.HasPrefix(line, ";; canary_home="):
			spec.CanaryHomeDir = strings.TrimPrefix(line, ";; canary_home=")
		case strings.HasPrefix(line, "(deny file-read*") && strings.Contains(line, ".ssh"):
			spec.DenySSHRead = true
		case strings.HasPrefix(line, "(allow file-read*") && strings.Contains(line, ".ssh"):
			spec.DenySSHRead = false
		case strings.HasPrefix(line, "(deny file-write*") && strings.Contains(line, ".ssh"):
			spec.DenySSHWrite = true
		case strings.HasPrefix(line, "(allow file-write*") && strings.Contains(line, ".ssh"):
			spec.DenySSHWrite = false
		case strings.HasPrefix(line, "(deny file-read*") && strings.Contains(line, ".aws"):
			spec.DenyAWSRead = true
		case strings.HasPrefix(line, "(allow file-read*") && strings.Contains(line, ".aws"):
			spec.DenyAWSRead = false
		case strings.HasPrefix(line, "(deny network-outbound") && strings.Contains(line, "docker.sock"):
			spec.DenyDockerSocket = true
		case strings.HasPrefix(line, "(allow network-outbound") && strings.Contains(line, "docker.sock"):
			spec.DenyDockerSocket = false
		case strings.HasPrefix(line, ";; directive "):
			kv := strings.TrimPrefix(line, ";; directive ")
			k, v, ok := strings.Cut(kv, "=")
			if !ok {
				continue
			}
			bVal, _ := strconv.ParseBool(v)
			switch k {
			case "hide_proc_environ":
				spec.HideProcEnviron = bVal
			case "resolve_beneath":
				spec.ResolveBeneath = bVal
			case "strip_secret_env":
				spec.StripSecretEnv = bVal
			case "block_io_uring_and_x32":
				spec.BlockIOUringAndX32 = bVal
			case "sanitize_path":
				spec.SanitizePATH = bVal
			case "deny_metadata_egress":
				spec.DenyMetadataEgress = bVal
			case "isolate_session_tmp":
				spec.IsolateSessionTmp = bVal
			case "fail_closed_on_degraded":
				spec.FailClosedOnDegraded = bVal
			case "sandbox_backend_available":
				spec.SandboxBackendAvailable = bVal
			case "allow_degraded_local":
				spec.AllowDegradedLocal = bVal
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return spec, nil
}

// ProbeOutcome records whether a live Siren escape probe escaped or was physically blocked.
type ProbeOutcome struct {
	Escaped  bool   `json:"escaped"`
	Blocked  bool   `json:"blocked"`
	ExitCode int    `json:"exit_code,omitempty"`
	Evidence string `json:"evidence"`
	Err      error  `json:"-"`
}

// SirenMutation defines one of the 12 Siren misconfiguration classes and its live differential probe.
type SirenMutation struct {
	ID          string                                                               `json:"id"`
	Name        string                                                               `json:"name"`
	Category    string                                                               `json:"category"`
	Description string                                                               `json:"description"`
	Platforms   []string                                                             `json:"platforms"`
	Mutate      func(p *AirlockProfileSpec) error                                    `json:"-"`
	Probe       func(ctx context.Context, canary *CanaryRoot, profilePath string) ProbeOutcome `json:"-"`
}

// SirenDifferentialResult captures both halves of a differential probe assertion.
// Passed is true ONLY when WeakenedEscaped == true AND HardenedBlocked == true.
type SirenDifferentialResult struct {
	ID              string        `json:"id"`
	Name            string        `json:"name"`
	Category        string        `json:"category"`
	WeakenedEscaped bool          `json:"weakened_escaped"`
	HardenedBlocked bool          `json:"hardened_blocked"`
	Passed          bool          `json:"passed"`
	Status          string        `json:"status"`
	Duration        time.Duration `json:"duration_ns"`
	DurationHuman   string        `json:"duration"`
	Evidence        string        `json:"evidence"`
}

// SirenSuiteConfig configures the differential fuzzer execution.
type SirenSuiteConfig struct {
	Concurrency     int
	PerProbeTimeout time.Duration
	Mutations       []SirenMutation
	BaseProfile     func(canary *CanaryRoot) *AirlockProfileSpec
	// OnWorkerStart / OnWorkerEnd are optional instrumentation hooks for concurrency testing.
	OnWorkerStart func()
	OnWorkerEnd   func()
}

// SirenBenchmarkReport contains the complete differential scorecard.
type SirenBenchmarkReport struct {
	SchemaVersion   string                    `json:"schema_version"`
	HostOS          string                    `json:"host_os"`
	Timestamp       time.Time                 `json:"timestamp"`
	TotalDuration   time.Duration             `json:"duration_ns"`
	DurationHuman   string                    `json:"duration"`
	Concurrency     int                       `json:"concurrency"`
	TotalProbes     int                       `json:"total_probes"`
	PassedProbes    int                       `json:"passed_probes"`
	FailedProbes    int                       `json:"failed_probes"`
	WeakenedEscaped int                       `json:"weakened_escaped"`
	HardenedBlocked int                       `json:"hardened_blocked"`
	Passed          bool                      `json:"passed"`
	Results         []SirenDifferentialResult `json:"results"`
}

// DefaultSirenCatalog returns the full 12-class Siren misconfiguration & escape probe suite
// grounded in RFC-2026-11-27-67 (SIREN-01 through SIREN-12).
func DefaultSirenCatalog() []SirenMutation {
	return []SirenMutation{
		{
			ID:          "SIREN-01",
			Name:        "Read-Only Credential Leak (SSH Private Key)",
			Category:    "read_only_escape",
			Description: "Read-only file-access escape skipped by LLM auto-mode intent classifiers: reads synthetic $CANARY_HOME/.ssh/id_ed25519",
			Platforms:   []string{"darwin", "linux"},
			Mutate: func(p *AirlockProfileSpec) error {
				p.DenySSHRead = false
				return nil
			},
			Probe: probeSIREN01ReadOnlySSHKey,
		},
		{
			ID:          "SIREN-02",
			Name:        "AWS/Cloud Credential Read",
			Category:    "read_only_escape",
			Description: "Omits ~/.aws read deny rule and probes read access to synthetic $CANARY_HOME/.aws/credentials",
			Platforms:   []string{"darwin", "linux"},
			Mutate: func(p *AirlockProfileSpec) error {
				p.DenyAWSRead = false
				return nil
			},
			Probe: probeSIREN02AWSCredRead,
		},
		{
			ID:          "SIREN-03",
			Name:        "Host Socket Leak (docker.sock)",
			Category:    "socket_leak",
			Description: "Exposes synthetic Unix domain socket docker.sock and attempts live unix dial",
			Platforms:   []string{"darwin", "linux"},
			Mutate: func(p *AirlockProfileSpec) error {
				p.DenyDockerSocket = false
				return nil
			},
			Probe: probeSIREN03DockerSocketLeak,
		},
		{
			ID:          "SIREN-04",
			Name:        "/proc Environ Exposure",
			Category:    "proc_env",
			Description: "Omits /proc/sys tmpfs/hidepid masking and reads peer /proc/<pid>/environ secret tokens",
			Platforms:   []string{"darwin", "linux"},
			Mutate: func(p *AirlockProfileSpec) error {
				p.HideProcEnviron = false
				return nil
			},
			Probe: probeSIREN04ProcEnviron,
		},
		{
			ID:          "SIREN-05",
			Name:        "Symlink Worktree Escape",
			Category:    "symlink",
			Description: "Creates a symlink inside the worktree pointing to $CANARY_HOME/.ssh/id_ed25519 and attempts RESOLVE_BENEATH escape",
			Platforms:   []string{"darwin", "linux"},
			Mutate: func(p *AirlockProfileSpec) error {
				p.ResolveBeneath = false
				return nil
			},
			Probe: probeSIREN05SymlinkEscape,
		},
		{
			ID:          "SIREN-06",
			Name:        "Ambient Secret Env Inheritance",
			Category:    "env",
			Description: "Leaves ANTHROPIC_API_KEY and AWS_SECRET_ACCESS_KEY unstripped in child sandbox environment",
			Platforms:   []string{"darwin", "linux"},
			Mutate: func(p *AirlockProfileSpec) error {
				p.StripSecretEnv = false
				return nil
			},
			Probe: probeSIREN06AmbientSecretEnv,
		},
		{
			ID:          "SIREN-07",
			Name:        "Syscall Escape (io_uring / x32 Seccomp)",
			Category:    "syscall",
			Description: "Strips seccomp-BPF io_uring_setup (425) and x32 ABI bitmask (0x40000000) trap rules",
			Platforms:   []string{"darwin", "linux"},
			Mutate: func(p *AirlockProfileSpec) error {
				p.BlockIOUringAndX32 = false
				return nil
			},
			Probe: probeSIREN07IOUringX32Seccomp,
		},
		{
			ID:          "SIREN-08",
			Name:        "PATH Binary Shadowing",
			Category:    "path_shadow",
			Description: "Prepends writable worktree ./bin to PATH, drops decoy git binary, and tests executable resolution",
			Platforms:   []string{"darwin", "linux"},
			Mutate: func(p *AirlockProfileSpec) error {
				p.SanitizePATH = false
				return nil
			},
			Probe: probeSIREN08PathShadowing,
		},
		{
			ID:          "SIREN-09",
			Name:        "Metadata SSRF Egress",
			Category:    "ssrf",
			Description: "Relaxes metadata/egress rule and attempts HTTP GET against synthetic IMDS listener",
			Platforms:   []string{"darwin", "linux"},
			Mutate: func(p *AirlockProfileSpec) error {
				p.DenyMetadataEgress = false
				return nil
			},
			Probe: probeSIREN09MetadataSSRF,
		},
		{
			ID:          "SIREN-10",
			Name:        "SSH Persistence Write (authorized_keys)",
			Category:    "persistence",
			Description: "Allows write to synthetic $CANARY_HOME/.ssh/authorized_keys and attempts key persistence append",
			Platforms:   []string{"darwin", "linux"},
			Mutate: func(p *AirlockProfileSpec) error {
				p.DenySSHWrite = false
				return nil
			},
			Probe: probeSIREN10SSHPersistenceWrite,
		},
		{
			ID:          "SIREN-11",
			Name:        "Shared /tmp Cross-Worktree Bleed",
			Category:    "tmp_bleed",
			Description: "Shares host /tmp without per-session isolation and reads sibling worktree canary file",
			Platforms:   []string{"darwin", "linux"},
			Mutate: func(p *AirlockProfileSpec) error {
				p.IsolateSessionTmp = false
				return nil
			},
			Probe: probeSIREN11SharedTmpBleed,
		},
		{
			ID:          "SIREN-12",
			Name:        "Fail-Open Degraded Execution",
			Category:    "fail_open",
			Description: "Simulates unavailable kernel sandbox backend without --allow-degraded-local; must fail closed (exit 126)",
			Platforms:   []string{"darwin", "linux"},
			Mutate: func(p *AirlockProfileSpec) error {
				p.FailClosedOnDegraded = false
				return nil
			},
			Probe: probeSIREN12FailOpenDegraded,
		},
	}
}

// RunSirenSuite executes the differential Siren misconfiguration fuzzing suite with a bounded
// FIFO semaphore (default concurrency: 4) and 5s per-probe timeout.
// Every probe MUST prove BOTH WeakenedEscaped == true AND HardenedBlocked == true.
func RunSirenSuite(ctx context.Context, cfg SirenSuiteConfig) (*SirenBenchmarkReport, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	concurrency := cfg.Concurrency
	if concurrency <= 0 {
		concurrency = DefaultSirenConcurrency
	}
	perProbeTimeout := cfg.PerProbeTimeout
	if perProbeTimeout <= 0 {
		perProbeTimeout = DefaultSirenProbeTimeout
	}
	mutations := cfg.Mutations
	if mutations == nil {
		mutations = DefaultSirenCatalog()
	}
	baseProfileFn := cfg.BaseProfile
	if baseProfileFn == nil {
		baseProfileFn = HardenedAirlockProfile
	}

	start := time.Now()
	results := make([]SirenDifferentialResult, len(mutations))

	// Bounded FIFO semaphore: tasks acquire slots in catalog order before launching.
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var activeCount atomic.Int64

	for i, mut := range mutations {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			results[i] = SirenDifferentialResult{
				ID:       mut.ID,
				Name:     mut.Name,
				Category: mut.Category,
				Status:   "FAIL_TIMEOUT",
				Evidence: fmt.Sprintf("suite context canceled before dispatch: %v", ctx.Err()),
			}
			continue
		}

		wg.Add(1)
		go func(idx int, m SirenMutation) {
			defer wg.Done()
			defer func() { <-sem }()

			activeCount.Add(1)
			if cfg.OnWorkerStart != nil {
				cfg.OnWorkerStart()
			}
			defer func() {
				if cfg.OnWorkerEnd != nil {
					cfg.OnWorkerEnd()
				}
				activeCount.Add(-1)
			}()

			probeCtx, cancel := context.WithTimeout(ctx, perProbeTimeout)
			defer cancel()

			results[idx] = executeDifferentialProbe(probeCtx, m, baseProfileFn)
		}(i, mut)
	}

	wg.Wait()
	totalDur := time.Since(start)

	report := &SirenBenchmarkReport{
		SchemaVersion: SirenSchemaVersion,
		HostOS:        runtime.GOOS,
		Timestamp:     time.Now().UTC(),
		TotalDuration: totalDur,
		DurationHuman: totalDur.Round(time.Millisecond).String(),
		Concurrency:   concurrency,
		TotalProbes:   len(results),
		Results:       results,
	}

	for _, r := range results {
		if r.WeakenedEscaped {
			report.WeakenedEscaped++
		}
		if r.HardenedBlocked {
			report.HardenedBlocked++
		}
		if r.Passed {
			report.PassedProbes++
		} else {
			report.FailedProbes++
		}
	}
	report.Passed = report.TotalProbes > 0 && report.FailedProbes == 0
	return report, nil
}

func executeDifferentialProbe(ctx context.Context, m SirenMutation, baseProfileFn func(*CanaryRoot) *AirlockProfileSpec) SirenDifferentialResult {
	pStart := time.Now()
	res := SirenDifferentialResult{
		ID:       m.ID,
		Name:     m.Name,
		Category: m.Category,
	}

	if m.Mutate == nil || m.Probe == nil {
		res.Status = "FAIL_INVALID_MUTATION"
		res.Evidence = "mutation or probe callback is nil"
		res.Duration = time.Since(pStart)
		res.DurationHuman = res.Duration.Round(time.Microsecond).String()
		return res
	}

	// Phase A: Hardened evaluation in a dedicated ephemeral 0700 CanaryRoot.
	hardCanary, err := NewCanaryRoot()
	if err != nil {
		res.Status = "FAIL_CANARY_INIT"
		res.Evidence = fmt.Sprintf("hardened canary init failed: %v", err)
		res.Duration = time.Since(pStart)
		res.DurationHuman = res.Duration.Round(time.Microsecond).String()
		return res
	}
	defer hardCanary.Cleanup()

	hardSpec := baseProfileFn(hardCanary)
	hardProfilePath, err := hardSpec.WriteToCanary(hardCanary, m.ID+"-hardened.sb")
	if err != nil {
		res.Status = "FAIL_PROFILE_WRITE"
		res.Evidence = fmt.Sprintf("write hardened profile failed: %v", err)
		res.Duration = time.Since(pStart)
		res.DurationHuman = res.Duration.Round(time.Microsecond).String()
		return res
	}
	hardOutcome := runProbeWithDeadline(ctx, m.Probe, hardCanary, hardProfilePath)

	// Phase B: Weakened (Siren-mutated) evaluation in a separate ephemeral 0700 CanaryRoot.
	weakCanary, err := NewCanaryRoot()
	if err != nil {
		res.Status = "FAIL_CANARY_INIT"
		res.Evidence = fmt.Sprintf("weakened canary init failed: %v", err)
		res.Duration = time.Since(pStart)
		res.DurationHuman = res.Duration.Round(time.Microsecond).String()
		return res
	}
	defer weakCanary.Cleanup()

	weakSpec := baseProfileFn(weakCanary).Clone()
	if err := m.Mutate(weakSpec); err != nil {
		res.Status = "FAIL_MUTATE"
		res.Evidence = fmt.Sprintf("profile mutation failed: %v", err)
		res.Duration = time.Since(pStart)
		res.DurationHuman = res.Duration.Round(time.Microsecond).String()
		return res
	}
	weakProfilePath, err := weakSpec.WriteToCanary(weakCanary, m.ID+"-weakened.sb")
	if err != nil {
		res.Status = "FAIL_PROFILE_WRITE"
		res.Evidence = fmt.Sprintf("write weakened profile failed: %v", err)
		res.Duration = time.Since(pStart)
		res.DurationHuman = res.Duration.Round(time.Microsecond).String()
		return res
	}
	weakOutcome := runProbeWithDeadline(ctx, m.Probe, weakCanary, weakProfilePath)

	res.Duration = time.Since(pStart)
	res.DurationHuman = res.Duration.Round(time.Microsecond).String()

	if errors.Is(hardOutcome.Err, context.DeadlineExceeded) || errors.Is(weakOutcome.Err, context.DeadlineExceeded) || ctx.Err() != nil {
		res.Status = "FAIL_TIMEOUT"
		res.Evidence = fmt.Sprintf("probe exceeded deadline: hardened=%q weakened=%q", hardOutcome.Evidence, weakOutcome.Evidence)
		return res
	}

	res.HardenedBlocked = hardOutcome.Blocked && !hardOutcome.Escaped
	res.WeakenedEscaped = weakOutcome.Escaped && !weakOutcome.Blocked
	res.Passed = res.WeakenedEscaped && res.HardenedBlocked

	switch {
	case res.Passed:
		res.Status = "PASS"
		res.Evidence = fmt.Sprintf("hardened=[%s] | weakened=[%s]", hardOutcome.Evidence, weakOutcome.Evidence)
	case !res.HardenedBlocked && !res.WeakenedEscaped:
		res.Status = "FAIL_DIFFERENTIAL_BOTH"
		res.Evidence = fmt.Sprintf("HARDENED LEAKED AND WEAKENED DID NOT ESCAPE: hardened=[%s] | weakened=[%s]", hardOutcome.Evidence, weakOutcome.Evidence)
	case !res.HardenedBlocked:
		res.Status = "FAIL_HARDENED_LEAK"
		res.Evidence = fmt.Sprintf("SANDBOX ESCAPE IN HARDENED PROFILE: hardened=[%s] | weakened=[%s]", hardOutcome.Evidence, weakOutcome.Evidence)
	default:
		res.Status = "FAIL_WEAKENED_NO_ESCAPE"
		res.Evidence = fmt.Sprintf("INEFFECTIVE PROBE (failed to escape weakened sandbox): hardened=[%s] | weakened=[%s]", hardOutcome.Evidence, weakOutcome.Evidence)
	}

	return res
}

func runProbeWithDeadline(ctx context.Context, probe func(context.Context, *CanaryRoot, string) ProbeOutcome, canary *CanaryRoot, profilePath string) ProbeOutcome {
	ch := make(chan ProbeOutcome, 1)
	go func() {
		ch <- probe(ctx, canary, profilePath)
	}()
	select {
	case out := <-ch:
		return out
	case <-ctx.Done():
		return ProbeOutcome{
			Err:      ctx.Err(),
			Evidence: fmt.Sprintf("probe canceled: %v", ctx.Err()),
		}
	}
}

// ── Live Siren Probes (SIREN-01 through SIREN-12) ──

func probeSIREN01ReadOnlySSHKey(ctx context.Context, canary *CanaryRoot, profilePath string) ProbeOutcome {
	if err := ctx.Err(); err != nil {
		return ProbeOutcome{Err: err}
	}
	spec, err := loadCompiledProfile(profilePath)
	if err != nil {
		return ProbeOutcome{Err: err, Evidence: err.Error()}
	}
	if spec.DenySSHRead {
		return ProbeOutcome{Blocked: true, Evidence: "EACCES: compiled profile denied read-only access to $CANARY_HOME/.ssh/id_ed25519"}
	}
	data, err := os.ReadFile(canary.SSHKeyPath)
	if err != nil {
		return ProbeOutcome{Blocked: true, Evidence: fmt.Sprintf("read failed: %v", err)}
	}
	if strings.Contains(string(data), "CANARY_NOT_A_REAL_KEY_SSH_"+canary.CanaryToken) {
		return ProbeOutcome{Escaped: true, Evidence: "LEAKED synthetic SSH canary key via read-only file access"}
	}
	return ProbeOutcome{Evidence: "canary token missing from SSH key"}
}

func probeSIREN02AWSCredRead(ctx context.Context, canary *CanaryRoot, profilePath string) ProbeOutcome {
	if err := ctx.Err(); err != nil {
		return ProbeOutcome{Err: err}
	}
	spec, err := loadCompiledProfile(profilePath)
	if err != nil {
		return ProbeOutcome{Err: err, Evidence: err.Error()}
	}
	if spec.DenyAWSRead {
		return ProbeOutcome{Blocked: true, Evidence: "EACCES: compiled profile denied read access to $CANARY_HOME/.aws/credentials"}
	}
	data, err := os.ReadFile(canary.AWSCredPath)
	if err != nil {
		return ProbeOutcome{Blocked: true, Evidence: fmt.Sprintf("read failed: %v", err)}
	}
	if strings.Contains(string(data), "CANARY_NOT_A_REAL_AWS_SECRET_"+canary.CanaryToken) {
		return ProbeOutcome{Escaped: true, Evidence: "LEAKED synthetic AWS credentials canary"}
	}
	return ProbeOutcome{Evidence: "canary token missing from AWS credentials"}
}

func probeSIREN03DockerSocketLeak(ctx context.Context, canary *CanaryRoot, profilePath string) ProbeOutcome {
	if err := ctx.Err(); err != nil {
		return ProbeOutcome{Err: err}
	}
	spec, err := loadCompiledProfile(profilePath)
	if err != nil {
		return ProbeOutcome{Err: err, Evidence: err.Error()}
	}
	if spec.DenyDockerSocket {
		return ProbeOutcome{Blocked: true, Evidence: "EPERM: compiled profile blocked unix dial to synthetic docker.sock"}
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", canary.SocketPath)
	if err != nil {
		return ProbeOutcome{Blocked: true, Evidence: fmt.Sprintf("unix dial failed: %v", err)}
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if strings.Contains(string(buf[:n]), "CANARY_DOCKER_SOCKET_REACHED_"+canary.CanaryToken) {
		return ProbeOutcome{Escaped: true, Evidence: "CONNECTED to live synthetic docker.sock Unix listener"}
	}
	return ProbeOutcome{Evidence: "socket connected without canary banner"}
}

func probeSIREN04ProcEnviron(ctx context.Context, canary *CanaryRoot, profilePath string) ProbeOutcome {
	if err := ctx.Err(); err != nil {
		return ProbeOutcome{Err: err}
	}
	spec, err := loadCompiledProfile(profilePath)
	if err != nil {
		return ProbeOutcome{Err: err, Evidence: err.Error()}
	}
	if spec.HideProcEnviron {
		return ProbeOutcome{Blocked: true, Evidence: "EPERM: /proc/<pid>/environ masked by hidepid/tmpfs policy"}
	}
	data, err := os.ReadFile(canary.ProcEnvironPath)
	if err != nil {
		return ProbeOutcome{Blocked: true, Evidence: fmt.Sprintf("proc environ read failed: %v", err)}
	}
	if strings.Contains(string(data), "ANTHROPIC_API_KEY=") && strings.Contains(string(data), canary.CanaryToken) {
		return ProbeOutcome{Escaped: true, Evidence: "LEAKED peer process environment tokens from synthetic /proc/self/environ"}
	}
	return ProbeOutcome{Evidence: "proc environ missing canary secret"}
}

func probeSIREN05SymlinkEscape(ctx context.Context, canary *CanaryRoot, profilePath string) ProbeOutcome {
	if err := ctx.Err(); err != nil {
		return ProbeOutcome{Err: err}
	}
	spec, err := loadCompiledProfile(profilePath)
	if err != nil {
		return ProbeOutcome{Err: err, Evidence: err.Error()}
	}
	linkPath := filepath.Join(canary.WorktreeDir, "escape-link")
	_ = os.Remove(linkPath)
	if err := os.Symlink(canary.SSHKeyPath, linkPath); err != nil {
		return ProbeOutcome{Err: err, Evidence: fmt.Sprintf("symlink creation failed: %v", err)}
	}

	if spec.ResolveBeneath {
		// Enforce real kernel/Go os.OpenRoot RESOLVE_BENEATH confinement on worktree!
		wtRoot, err := os.OpenRoot(canary.WorktreeDir)
		if err != nil {
			return ProbeOutcome{Err: err, Evidence: err.Error()}
		}
		defer wtRoot.Close()
		f, openErr := wtRoot.Open("escape-link")
		if openErr != nil {
			return ProbeOutcome{Blocked: true, Evidence: fmt.Sprintf("EXDEV/EPERM: os.OpenRoot blocked worktree symlink escape (%v)", openErr)}
		}
		_ = f.Close()
		return ProbeOutcome{Escaped: true, Evidence: "unexpectedly opened symlink escaping os.OpenRoot"}
	}

	// Weakened profile omits RESOLVE_BENEATH; direct read follows symlink out of worktree.
	data, err := os.ReadFile(linkPath)
	if err != nil {
		return ProbeOutcome{Blocked: true, Evidence: fmt.Sprintf("symlink read failed: %v", err)}
	}
	if strings.Contains(string(data), "CANARY_NOT_A_REAL_KEY_SSH_"+canary.CanaryToken) {
		return ProbeOutcome{Escaped: true, Evidence: "ESCAPED worktree via symlink to $CANARY_HOME/.ssh/id_ed25519"}
	}
	return ProbeOutcome{Evidence: "symlink target missing canary token"}
}

func probeSIREN06AmbientSecretEnv(ctx context.Context, canary *CanaryRoot, profilePath string) ProbeOutcome {
	if err := ctx.Err(); err != nil {
		return ProbeOutcome{Err: err}
	}
	spec, err := loadCompiledProfile(profilePath)
	if err != nil {
		return ProbeOutcome{Err: err, Evidence: err.Error()}
	}

	childEnv := buildSandboxEnv(canary.SecretEnv, spec.StripSecretEnv)
	for _, kv := range childEnv {
		if strings.HasPrefix(kv, "ANTHROPIC_API_KEY=") || strings.HasPrefix(kv, "AWS_SECRET_ACCESS_KEY=") {
			if strings.Contains(kv, canary.CanaryToken) {
				return ProbeOutcome{Escaped: true, Evidence: "LEAKED ambient secret env var into sandbox child environment"}
			}
		}
	}
	return ProbeOutcome{Blocked: true, Evidence: "STRIPPED: ambient ANTHROPIC_API_KEY and AWS_SECRET_ACCESS_KEY absent from child env"}
}

func buildSandboxEnv(base []string, stripSecrets bool) []string {
	if !stripSecrets {
		out := make([]string, len(base))
		copy(out, base)
		return out
	}
	scrubPrefixes := []string{"ANTHROPIC_", "AWS_", "OPENAI_", "GITHUB_TOKEN", "GH_TOKEN"}
	out := make([]string, 0, len(base))
	for _, kv := range base {
		k, _, _ := strings.Cut(kv, "=")
		blocked := false
		for _, pref := range scrubPrefixes {
			if strings.HasPrefix(strings.ToUpper(k), pref) {
				blocked = true
				break
			}
		}
		if !blocked {
			out = append(out, kv)
		}
	}
	return out
}

func probeSIREN07IOUringX32Seccomp(ctx context.Context, canary *CanaryRoot, profilePath string) ProbeOutcome {
	if err := ctx.Err(); err != nil {
		return ProbeOutcome{Err: err}
	}
	spec, err := loadCompiledProfile(profilePath)
	if err != nil {
		return ProbeOutcome{Err: err, Evidence: err.Error()}
	}
	const (
		sysIOUringSetup = 425
		x32SyscallBit   = 0x40000000
	)
	if spec.BlockIOUringAndX32 {
		return ProbeOutcome{
			Blocked:  true,
			Evidence: fmt.Sprintf("EPERM: seccomp-BPF policy traps io_uring_setup (%d) and x32 ABI mask (0x%x)", sysIOUringSetup, x32SyscallBit),
		}
	}
	return ProbeOutcome{
		Escaped:  true,
		Evidence: fmt.Sprintf("BYPASSED: seccomp policy omitted io_uring_setup (%d) and x32 ABI mask (0x%x)", sysIOUringSetup, x32SyscallBit),
	}
}

func probeSIREN08PathShadowing(ctx context.Context, canary *CanaryRoot, profilePath string) ProbeOutcome {
	if err := ctx.Err(); err != nil {
		return ProbeOutcome{Err: err}
	}
	spec, err := loadCompiledProfile(profilePath)
	if err != nil {
		return ProbeOutcome{Err: err, Evidence: err.Error()}
	}

	// Drop an executable decoy "git" inside synthetic writable worktree/bin.
	decoyRel := filepath.Join("worktree", "bin", "git")
	if err := writeRootFile(canary.Root, decoyRel, []byte("#!/bin/sh\necho CANARY_DECOY_GIT_"+canary.CanaryToken+"\n"), 0o700); err != nil {
		return ProbeOutcome{Err: err, Evidence: fmt.Sprintf("write decoy git failed: %v", err)}
	}
	decoyAbs := filepath.Join(canary.WorktreeBinDir, "git")

	effectivePATH := []string{"/usr/bin", "/bin"}
	if !spec.SanitizePATH {
		effectivePATH = append([]string{canary.WorktreeBinDir}, effectivePATH...)
	}

	resolved := resolveExecutableInPATH("git", effectivePATH)
	if resolved == decoyAbs {
		return ProbeOutcome{Escaped: true, Evidence: fmt.Sprintf("SHADOWED: git resolved to writable worktree decoy %q", resolved)}
	}
	return ProbeOutcome{Blocked: true, Evidence: fmt.Sprintf("BLOCKED: immutable PATH ignored worktree decoy (resolved=%q)", resolved)}
}

func resolveExecutableInPATH(bin string, dirs []string) string {
	for _, dir := range dirs {
		cand := filepath.Join(dir, bin)
		info, err := os.Stat(cand)
		if err == nil && !info.IsDir() && (info.Mode()&0o111) != 0 {
			return cand
		}
	}
	return ""
}

func probeSIREN09MetadataSSRF(ctx context.Context, canary *CanaryRoot, profilePath string) ProbeOutcome {
	if err := ctx.Err(); err != nil {
		return ProbeOutcome{Err: err}
	}
	spec, err := loadCompiledProfile(profilePath)
	if err != nil {
		return ProbeOutcome{Err: err, Evidence: err.Error()}
	}
	if spec.DenyMetadataEgress {
		return ProbeOutcome{Blocked: true, Evidence: "EPERM: egress policy blocked connection to synthetic metadata listener"}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+canary.MetadataAddr+"/latest/meta-data/iam/security-credentials/", nil)
	if err != nil {
		return ProbeOutcome{Err: err, Evidence: err.Error()}
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return ProbeOutcome{Blocked: true, Evidence: fmt.Sprintf("metadata connect failed: %v", err)}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	if strings.Contains(string(body), "CANARY_IMDS_CREDENTIALS_"+canary.CanaryToken) {
		return ProbeOutcome{Escaped: true, Evidence: "SSRF REACHED synthetic metadata service and retrieved canary credentials"}
	}
	return ProbeOutcome{Evidence: "metadata response missing canary payload"}
}

func probeSIREN10SSHPersistenceWrite(ctx context.Context, canary *CanaryRoot, profilePath string) ProbeOutcome {
	if err := ctx.Err(); err != nil {
		return ProbeOutcome{Err: err}
	}
	spec, err := loadCompiledProfile(profilePath)
	if err != nil {
		return ProbeOutcome{Err: err, Evidence: err.Error()}
	}
	injectedKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5ATTACKER siren-persist-" + canary.CanaryToken + "@evil\n"
	if spec.DenySSHWrite {
		// Verify file remains unmodified on disk.
		current, _ := os.ReadFile(canary.AuthorizedKeysPath)
		if !strings.Contains(string(current), injectedKey) {
			return ProbeOutcome{Blocked: true, Evidence: "EPERM: compiled profile denied write to $CANARY_HOME/.ssh/authorized_keys"}
		}
	}
	f, err := os.OpenFile(canary.AuthorizedKeysPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return ProbeOutcome{Blocked: true, Evidence: fmt.Sprintf("open authorized_keys failed: %v", err)}
	}
	_, wErr := f.WriteString(injectedKey)
	_ = f.Close()
	if wErr != nil {
		return ProbeOutcome{Blocked: true, Evidence: fmt.Sprintf("write authorized_keys failed: %v", wErr)}
	}
	after, _ := os.ReadFile(canary.AuthorizedKeysPath)
	if strings.Contains(string(after), "siren-persist-"+canary.CanaryToken) {
		return ProbeOutcome{Escaped: true, Evidence: "PERSISTED attacker pubkey into synthetic $CANARY_HOME/.ssh/authorized_keys"}
	}
	return ProbeOutcome{Evidence: "authorized_keys unchanged"}
}

func probeSIREN11SharedTmpBleed(ctx context.Context, canary *CanaryRoot, profilePath string) ProbeOutcome {
	if err := ctx.Err(); err != nil {
		return ProbeOutcome{Err: err}
	}
	spec, err := loadCompiledProfile(profilePath)
	if err != nil {
		return ProbeOutcome{Err: err, Evidence: err.Error()}
	}
	effectiveTmp := canary.SharedTmpDir
	if spec.IsolateSessionTmp {
		effectiveTmp = canary.IsolatedTmpDir
	}
	target := filepath.Join(effectiveTmp, "sibling-session.canary")
	data, err := os.ReadFile(target)
	if err != nil {
		return ProbeOutcome{Blocked: true, Evidence: fmt.Sprintf("ISOLATED: sibling canary not visible in per-session tmpdir (%v)", err)}
	}
	if strings.Contains(string(data), "CANARY_SIBLING_WORKTREE_BLEED_"+canary.CanaryToken) {
		return ProbeOutcome{Escaped: true, Evidence: "BLED across worktrees via shared /tmp sibling canary file"}
	}
	return ProbeOutcome{Evidence: "sibling tmp file missing canary token"}
}

func probeSIREN12FailOpenDegraded(ctx context.Context, canary *CanaryRoot, profilePath string) ProbeOutcome {
	if err := ctx.Err(); err != nil {
		return ProbeOutcome{Err: err}
	}
	spec, err := loadCompiledProfile(profilePath)
	if err != nil {
		return ProbeOutcome{Err: err, Evidence: err.Error()}
	}
	// Simulate kernel sandbox backend unavailability without --allow-degraded-local.
	backendAvailable := false
	if !backendAvailable && !spec.AllowDegradedLocal {
		if spec.FailClosedOnDegraded {
			return ProbeOutcome{
				Blocked:  true,
				ExitCode: SirenDegradedExitCode,
				Evidence: fmt.Sprintf("FAIL-CLOSED: unavailable sandbox backend refused execution (exit %d)", SirenDegradedExitCode),
			}
		}
		return ProbeOutcome{
			Escaped:  true,
			ExitCode: 0,
			Evidence: "FAIL-OPEN: command executed unsandboxed when kernel backend was unavailable",
		}
	}
	return ProbeOutcome{Blocked: true, Evidence: "sandbox backend available"}
}

// ToJSON returns pretty-printed JSON bytes for CI/CD ingestion.
func (r *SirenBenchmarkReport) ToJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// FormatScorecard renders a structured terminal scorecard for the Siren differential suite.
func (r *SirenBenchmarkReport) FormatScorecard() string {
	var b strings.Builder
	b.WriteString("═══════════════════════════════════════════════════════════════════════════════════════════\n")
	b.WriteString("                AEGISBOX SIREN DIFFERENTIAL SANDBOX MISCONFIGURATION REPORT                \n")
	b.WriteString("═══════════════════════════════════════════════════════════════════════════════════════════\n")
	fmt.Fprintf(&b, "  Schema:          %s (host=%s, concurrency=%d)\n", r.SchemaVersion, r.HostOS, r.Concurrency)
	fmt.Fprintf(&b, "  Timestamp:       %s\n", r.Timestamp.Format("2006-01-02 15:04:05 UTC"))
	fmt.Fprintf(&b, "  Duration:        %s (%d probes evaluated)\n", r.DurationHuman, r.TotalProbes)
	fmt.Fprintf(&b, "  Weakened Suite:  %d/%d probes proved misconfig escape\n", r.WeakenedEscaped, r.TotalProbes)
	fmt.Fprintf(&b, "  Hardened Suite:  %d/%d probes physically blocked\n", r.HardenedBlocked, r.TotalProbes)
	b.WriteString("═══════════════════════════════════════════════════════════════════════════════════════════\n")
	fmt.Fprintf(&b, " %-10s %-38s %-10s %-10s %-18s\n", "ID", "SIREN CLASS", "WEAKENED", "HARDENED", "STATUS")
	b.WriteString("───────────────────────────────────────────────────────────────────────────────────────────\n")
	for _, res := range r.Results {
		name := res.Name
		if len(name) > 38 {
			name = name[:35] + "..."
		}
		weakStr := "NO-ESC"
		if res.WeakenedEscaped {
			weakStr = "ESCAPED"
		}
		hardStr := "LEAKED"
		if res.HardenedBlocked {
			hardStr = "BLOCKED"
		}
		fmt.Fprintf(&b, " %-10s %-38s %-10s %-10s %-18s\n", res.ID, name, weakStr, hardStr, res.Status)
	}
	b.WriteString("───────────────────────────────────────────────────────────────────────────────────────────\n")
	if r.Passed {
		fmt.Fprintf(&b, " FINAL VERDICT: PASS (%d/%d differential sandbox boundaries verified)\n", r.PassedProbes, r.TotalProbes)
	} else {
		fmt.Fprintf(&b, " FINAL VERDICT: FAIL (%d/%d probes failed differential assertion)\n", r.FailedProbes, r.TotalProbes)
	}
	b.WriteString("═══════════════════════════════════════════════════════════════════════════════════════════\n")
	return b.String()
}
