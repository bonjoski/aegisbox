package learn

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	// Synthetic non-functional decoy credentials strictly confined inside ephemeral kata workspaces.
	DecoySSHPrivateKey = "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
		"AEGISBOX_KATA_DECOY_KEY_NOT_REAL_DO_NOT_USE_0001\n" +
		"-----END OPENSSH PRIVATE KEY-----\n"
	DecoyOpenAIKey     = "sk-decoy-kata02-aegisbox000000000000000000"
	DecoyCanaryToken   = "bonjoski_canary_tok_kata05_7c6b5a493827"
	DecoyCanaryPII     = "bonjoski_canary_pii_ssn_000_00_0000"
)

// KataWorkspace encapsulates an ephemeral 0700 kata directory opened via Go's kernel-confined
// os.OpenRoot (O_NOFOLLOW), with a completely isolated decoy $HOME that never touches real host $HOME.
type KataWorkspace struct {
	RootDir   string
	DecoyHome string
	root      *os.Root
	ephemeral bool
}

// NewKataWorkspace provisions an isolated 0700 kata workspace and decoy $HOME via os.OpenRoot.
func NewKataWorkspace(kataID, customDir string) (*KataWorkspace, error) {
	var rootDir string
	ephemeral := false
	if strings.TrimSpace(customDir) != "" {
		abs, err := filepath.Abs(customDir)
		if err != nil {
			return nil, fmt.Errorf("invalid kata workspace path: %w", err)
		}
		if err := os.MkdirAll(abs, 0700); err != nil {
			return nil, fmt.Errorf("create kata workspace %q: %w", abs, err)
		}
		_ = os.Chmod(abs, 0700)
		rootDir = abs
	} else {
		tmp, err := os.MkdirTemp("", fmt.Sprintf("aegisbox-%s-*", sanitizeSlug(kataID)))
		if err != nil {
			return nil, fmt.Errorf("create ephemeral kata workspace: %w", err)
		}
		if err := os.Chmod(tmp, 0700); err != nil {
			_ = os.RemoveAll(tmp)
			return nil, fmt.Errorf("chmod ephemeral kata workspace: %w", err)
		}
		rootDir = tmp
		ephemeral = true
	}

	root, err := os.OpenRoot(rootDir)
	if err != nil {
		if ephemeral {
			_ = os.RemoveAll(rootDir)
		}
		return nil, fmt.Errorf("open kernel-confined kata root %q: %w", rootDir, err)
	}

	ws := &KataWorkspace{
		RootDir:   rootDir,
		DecoyHome: filepath.Join(rootDir, "decoy-home"),
		root:      root,
		ephemeral: ephemeral,
	}

	// Provision isolated decoy $HOME structure inside os.OpenRoot (never touching real host $HOME).
	if err := ws.MkdirAll("decoy-home/.ssh", 0700); err != nil {
		ws.Close()
		return nil, err
	}
	if err := ws.MkdirAll("app", 0700); err != nil {
		ws.Close()
		return nil, err
	}
	if err := ws.WriteFile("decoy-home/.ssh/id_rsa", []byte(DecoySSHPrivateKey), 0600); err != nil {
		ws.Close()
		return nil, err
	}

	return ws, nil
}

// MkdirAll creates nested directories strictly inside the os.OpenRoot confinement boundary.
func (w *KataWorkspace) MkdirAll(relPath string, perm os.FileMode) error {
	clean := filepath.Clean(relPath)
	if filepath.IsAbs(clean) || strings.HasPrefix(clean, "..") {
		return fmt.Errorf("security violation: path %q escapes kata workspace", relPath)
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
		if _, err := w.root.Lstat(cur); err != nil {
			if os.IsNotExist(err) {
				if mkErr := w.root.Mkdir(cur, perm); mkErr != nil {
					return mkErr
				}
			} else {
				return err
			}
		}
	}
	return nil
}

// WriteFile writes a file strictly inside the os.OpenRoot boundary (O_NOFOLLOW).
func (w *KataWorkspace) WriteFile(relPath string, data []byte, perm os.FileMode) error {
	clean := filepath.Clean(relPath)
	if filepath.IsAbs(clean) || strings.HasPrefix(clean, "..") {
		return fmt.Errorf("security violation: write path %q escapes kata workspace", relPath)
	}
	if dir := filepath.Dir(clean); dir != "." && dir != "" {
		if err := w.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	f, err := w.root.OpenFile(clean, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	return err
}

// ReadFile reads a file strictly inside the os.OpenRoot boundary (refuses escaping symlinks or ..).
func (w *KataWorkspace) ReadFile(relPath string) ([]byte, error) {
	clean := filepath.Clean(relPath)
	if filepath.IsAbs(clean) || strings.HasPrefix(clean, "..") {
		return nil, fmt.Errorf("security violation: read path %q escapes kata workspace", relPath)
	}
	f, err := w.root.Open(clean)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 1024*1024))
}

// IsolatedEnv returns a sanitized process environment pointing HOME strictly at DecoyHome.
func (w *KataWorkspace) IsolatedEnv() []string {
	return []string{
		"HOME=" + w.DecoyHome,
		"TMPDIR=" + filepath.Join(w.RootDir, "tmp"),
		"LOCKSMITH_MOCK_BACKEND=1",
		"AEGISBOX_KATA_AIRGAP=1",
		"NO_PROXY=*",
	}
}

// Close releases the os.OpenRoot descriptor and removes ephemeral workspace directories.
func (w *KataWorkspace) Close() error {
	var firstErr error
	if w.root != nil {
		if err := w.root.Close(); err != nil {
			firstErr = err
		}
		w.root = nil
	}
	if w.ephemeral && w.RootDir != "" {
		if err := os.RemoveAll(w.RootDir); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func sanitizeSlug(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "kata"
	}
	return b.String()
}
