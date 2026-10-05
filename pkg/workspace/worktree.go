package workspace

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// GitWorktreeSession implements SessionWorkspace using detached git worktrees.
type GitWorktreeSession struct {
	id          string
	baseDir     string
	shadowDir   string
	branchName  string
	config      ShadowConfig
	maskedPaths []string
}

// CreateSession initializes a new ephemeral shadow workspace for a task.
func (m *WorkspaceManager) CreateSession(ctx context.Context, cfg ShadowConfig) (SessionWorkspace, error) {
	randBytes := make([]byte, 8)
	if _, err := rand.Read(randBytes); err != nil {
		return nil, fmt.Errorf("failed to generate session id: %w", err)
	}
	sessionID := hex.EncodeToString(randBytes)
	shadowDir := filepath.Join(m.sessionsDir, sessionID)

	// Check if baseDir is inside a git repo
	isGit := isGitRepo(cfg.BaseDir)

	if isGit && cfg.Mode != ModeDirect {
		branchName := fmt.Sprintf("ironbox-shadow-%s", sessionID)
		cmd := exec.CommandContext(ctx, "git", "worktree", "add", "-b", branchName, shadowDir, "HEAD")
		cmd.Dir = cfg.BaseDir
		var errBuf bytes.Buffer
		cmd.Stderr = &errBuf
		if err := cmd.Run(); err != nil {
			// Fallback to directory copy if worktree fails (e.g. no commits yet)
			if err := copyDirectory(cfg.BaseDir, shadowDir); err != nil {
				return nil, fmt.Errorf("git worktree failed (%s) and fallback copy failed: %w", errBuf.String(), err)
			}
		}

		session := &GitWorktreeSession{
			id:         sessionID,
			baseDir:    cfg.BaseDir,
			shadowDir:  shadowDir,
			branchName: branchName,
			config:     cfg,
		}

		// Apply security masking
		if err := session.applyMasking(); err != nil {
			_ = session.Cleanup(ctx)
			return nil, fmt.Errorf("failed to apply security masking: %w", err)
		}

		// Inject synthetic credentials
		if err := session.injectSyntheticEnv(); err != nil {
			_ = session.Cleanup(ctx)
			return nil, fmt.Errorf("failed to inject synthetic env: %w", err)
		}

		return session, nil
	}

	// Non-git or Direct fallback
	if err := os.MkdirAll(shadowDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create shadow dir: %w", err)
	}
	if err := copyDirectory(cfg.BaseDir, shadowDir); err != nil {
		_ = os.RemoveAll(shadowDir)
		return nil, fmt.Errorf("failed to copy workspace: %w", err)
	}

	session := &GitWorktreeSession{
		id:        sessionID,
		baseDir:   cfg.BaseDir,
		shadowDir: shadowDir,
		config:    cfg,
	}

	_ = session.applyMasking()
	_ = session.injectSyntheticEnv()
	return session, nil
}

func (s *GitWorktreeSession) ID() string {
	return s.id
}

func (s *GitWorktreeSession) ShadowDir() string {
	return s.shadowDir
}

func (s *GitWorktreeSession) applyMasking() error {
	// Standard sensitive paths to mask / make non-leaking
	masks := []string{
		filepath.Join(s.shadowDir, ".env"),
		filepath.Join(s.shadowDir, ".env.local"),
		filepath.Join(s.shadowDir, ".git", "hooks"),
	}

	for _, pattern := range s.config.MaskPatterns {
		if pattern != "" {
			matches, _ := filepath.Glob(filepath.Join(s.shadowDir, pattern))
			masks = append(masks, matches...)
		}
	}

	for _, p := range masks {
		if info, err := os.Stat(p); err == nil {
			if info.IsDir() {
				// Remove write permissions on directory
				if err := os.Chmod(p, 0555); err != nil {
					// Best-effort masking on directories
					continue
				}
			} else {
				// Replace sensitive file content with dummy comment
				if err := os.WriteFile(p, []byte("# [IRONBOX MASKED] Contents hidden from untrusted execution context\n"), 0444); err != nil {
					continue
				}
			}
			s.maskedPaths = append(s.maskedPaths, p)
		}
	}


	return nil
}

func (s *GitWorktreeSession) injectSyntheticEnv() error {
	if len(s.config.SyntheticEnv) == 0 {
		return nil
	}

	envFile := filepath.Join(s.shadowDir, ".env.synthetic")
	var buf strings.Builder
	buf.WriteString("# Synthetic Dummy Environment injected by Ironbox\n")
	for k, v := range s.config.SyntheticEnv {
		buf.WriteString(fmt.Sprintf("%s=%s\n", k, v))
	}
	return os.WriteFile(envFile, []byte(buf.String()), 0600)
}

func (s *GitWorktreeSession) CaptureDiff(ctx context.Context) (*DiffReport, error) {
	report := &DiffReport{
		SessionID:   s.id,
		GeneratedAt: time.Now(),
		FilesAdded:  make([]string, 0),
		FilesModified: make([]string, 0),
		FilesDeleted: make([]string, 0),
	}

	if isGitRepo(s.shadowDir) {
		cmd := exec.CommandContext(ctx, "git", "status", "--porcelain")
		cmd.Dir = s.shadowDir
		output, err := cmd.Output()
		if err == nil {
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if len(line) < 3 {
					continue
				}
				status := line[:2]
				file := strings.TrimSpace(line[3:])
				switch {
				case strings.Contains(status, "?") || strings.Contains(status, "A"):
					report.FilesAdded = append(report.FilesAdded, file)
				case strings.Contains(status, "M"):
					report.FilesModified = append(report.FilesModified, file)
				case strings.Contains(status, "D"):
					report.FilesDeleted = append(report.FilesDeleted, file)
				}
			}
		}

		diffCmd := exec.CommandContext(ctx, "git", "diff")
		diffCmd.Dir = s.shadowDir
		diffOut, _ := diffCmd.Output()
		report.RawDiff = string(diffOut)
	}

	return report, nil
}

func (s *GitWorktreeSession) ApplyToHost(ctx context.Context) error {
	diff, err := s.CaptureDiff(ctx)
	if err != nil {
		return fmt.Errorf("failed to capture diff: %w", err)
	}

	// Copy modified and added files back to baseDir
	allChanged := append(diff.FilesAdded, diff.FilesModified...)
	for _, rel := range allChanged {
		src := filepath.Join(s.shadowDir, rel)
		dst := filepath.Join(s.baseDir, rel)

		if strings.HasPrefix(rel, ".git") {
			// Never copy back .git modifications
			continue
		}

		if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
			return fmt.Errorf("failed to create host directory for %q: %w", rel, err)
		}

		data, err := os.ReadFile(src)
		if err != nil {
			continue
		}
		if err := os.WriteFile(dst, data, 0644); err != nil {
			return fmt.Errorf("failed to write %q to host workspace: %w", dst, err)
		}
	}

	return nil
}

func (s *GitWorktreeSession) Cleanup(ctx context.Context) error {
	if s.branchName != "" && isGitRepo(s.baseDir) {
		// Prune worktree
		cmd := exec.CommandContext(ctx, "git", "worktree", "remove", "--force", s.shadowDir)
		cmd.Dir = s.baseDir
		if err := cmd.Run(); err != nil {
			// Non-fatal if worktree was already detached
		}

		// Delete temporary branch
		delCmd := exec.CommandContext(ctx, "git", "branch", "-D", s.branchName)
		delCmd.Dir = s.baseDir
		if err := delCmd.Run(); err != nil {
			// Non-fatal if branch was already pruned
		}
	}

	if err := os.RemoveAll(s.shadowDir); err != nil {
		return fmt.Errorf("failed to remove shadow dir %q: %w", s.shadowDir, err)
	}
	return nil
}



func isGitRepo(dir string) bool {
	gitDir := filepath.Join(dir, ".git")
	info, err := os.Stat(gitDir)
	return err == nil && (info.IsDir() || !info.IsDir())
}

func copyDirectory(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if rel == "." || strings.HasPrefix(rel, ".git") {
			return nil
		}

		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, info.Mode())
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, info.Mode())
	})
}
