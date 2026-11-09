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

	"github.com/bonjoski/aegisbox/pkg/argus"
)

// GitWorktreeSession implements SessionWorkspace using detached git worktrees.
type GitWorktreeSession struct {
	id            string
	baseDir       string
	shadowDir     string
	branchName    string
	config        ShadowConfig
	maskedPaths   []string
	injectedFiles []string
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
		branchName := fmt.Sprintf("aegisbox-shadow-%s", sessionID)
		cmd := exec.CommandContext(ctx, "git", "worktree", "add", "-b", branchName, shadowDir, "HEAD")

		cmd.Dir = cfg.BaseDir
		var errBuf bytes.Buffer
		cmd.Stderr = &errBuf
		if err := cmd.Run(); err != nil {
			branchName = "" // not a git worktree
			// Fallback to directory copy if worktree fails (e.g. no commits yet)
			if err := os.MkdirAll(shadowDir, 0700); err != nil {
				return nil, fmt.Errorf("failed to create shadow dir: %w", err)
			}
			if err := copyDirectory(cfg.BaseDir, shadowDir); err != nil {
				_ = os.RemoveAll(shadowDir)
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

		// Inject specified host files
		if err := session.injectFiles(); err != nil {
			_ = session.Cleanup(ctx)
			return nil, fmt.Errorf("failed to inject files: %w", err)
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

	if err := session.applyMasking(); err != nil {
		_ = session.Cleanup(ctx)
		return nil, fmt.Errorf("failed to apply security masking: %w", err)
	}
	if err := session.injectSyntheticEnv(); err != nil {
		_ = session.Cleanup(ctx)
		return nil, fmt.Errorf("failed to inject synthetic env: %w", err)
	}
	if err := session.injectFiles(); err != nil {
		_ = session.Cleanup(ctx)
		return nil, fmt.Errorf("failed to inject files: %w", err)
	}
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
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		matches, _ := filepath.Glob(filepath.Join(s.shadowDir, pattern))
		masks = append(masks, matches...)
	}

	// Also walk subdirectories for nested .env / .env.* files so secrets in monorepo packages are masked
	_ = filepath.Walk(s.shadowDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		rel, rErr := filepath.Rel(s.shadowDir, path)
		if rErr != nil || rel == "." {
			return nil
		}
		if rel == ".git" || strings.HasPrefix(rel, ".git"+string(filepath.Separator)) {
			if info.IsDir() && rel != filepath.Join(".git", "hooks") {
				return nil
			}
		}
		base := filepath.Base(path)
		if !info.IsDir() && base != ".env.synthetic" && (base == ".env" || strings.HasPrefix(base, ".env.")) {
			masks = append(masks, path)
		}
		return nil
	})

	seen := make(map[string]bool)
	for _, p := range masks {
		cleanP := filepath.Clean(p)
		if seen[cleanP] {
			continue
		}
		seen[cleanP] = true

		info, err := os.Lstat(cleanP)
		if err != nil {
			continue
		}
		rel, rErr := filepath.Rel(s.shadowDir, cleanP)
		if rErr != nil || rel == "." || strings.HasPrefix(rel, "..") {
			continue
		}

		if info.IsDir() {
			if chmodErr := os.Chmod(cleanP, 0555); chmodErr != nil {
				continue
			}
		} else {
			// Make writable temporarily if read-only before replacing with placeholder
			if chmodErr := os.Chmod(cleanP, 0600); chmodErr != nil && !os.IsNotExist(chmodErr) {
				// Non-fatal if chmod fails
			}
			if writeErr := os.WriteFile(cleanP, []byte("# [AEGISBOX MASKED] Contents hidden from untrusted execution context\n"), 0444); writeErr != nil {
				continue
			}
		}
		s.maskedPaths = append(s.maskedPaths, filepath.Clean(rel))
	}

	return nil
}

func (s *GitWorktreeSession) isMasked(rel string) bool {
	cleaned := filepath.Clean(rel)
	base := filepath.Base(cleaned)
	if base != ".env.synthetic" && (base == ".env" || strings.HasPrefix(base, ".env.")) {
		return true
	}
	for _, m := range s.maskedPaths {
		cleanMask := filepath.Clean(m)
		if cleaned == cleanMask || strings.HasPrefix(cleaned, cleanMask+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func (s *GitWorktreeSession) shouldExcludeFromSync(rel string) bool {
	cleaned := filepath.Clean(rel)
	if cleaned == "." ||
		cleaned == ".git" ||
		strings.HasPrefix(cleaned, ".git"+string(filepath.Separator)) ||
		cleaned == ".env.synthetic" ||
		s.isInjected(cleaned) ||
		s.isMasked(cleaned) {
		return true
	}
	return false
}

func (s *GitWorktreeSession) injectSyntheticEnv() error {
	if len(s.config.SyntheticEnv) == 0 {
		return nil
	}

	envFile := filepath.Join(s.shadowDir, ".env.synthetic")
	var buf strings.Builder
	buf.WriteString("# Synthetic Dummy Environment injected by Aegisbox\n")

	for k, v := range s.config.SyntheticEnv {
		buf.WriteString(fmt.Sprintf("%s=%s\n", k, v))
	}
	return os.WriteFile(envFile, []byte(buf.String()), 0600)
}

func resolveSourcePath(baseDir, path string) (string, error) {
	if strings.HasPrefix(path, "~/") || path == "~" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("failed to resolve user home directory: %w", err)
		}
		if path == "~" {
			path = home
		} else {
			path = filepath.Join(home, strings.TrimPrefix(path, "~/"))
		}
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(baseDir, path)
	}
	return filepath.Clean(path), nil
}

func (s *GitWorktreeSession) isInjected(rel string) bool {
	cleaned := filepath.Clean(rel)
	for _, inj := range s.injectedFiles {
		if filepath.Clean(inj) == cleaned {
			return true
		}
	}
	return false
}

func (s *GitWorktreeSession) injectFiles() error {
	if len(s.config.InjectFiles) == 0 {
		return nil
	}

	shadowGuard, err := NewSafePathGuard(s.shadowDir)
	if err != nil {
		return fmt.Errorf("failed to initialize shadow path guard: %w", err)
	}

	for targetRel, srcPath := range s.config.InjectFiles {
		targetRel = strings.TrimSpace(targetRel)
		srcPath = strings.TrimSpace(srcPath)
		if targetRel == "" || srcPath == "" {
			return fmt.Errorf("invalid inject entry: target and source path must not be empty")
		}

		cleanTarget := filepath.Clean(targetRel)
		if cleanTarget == ".git" || strings.HasPrefix(cleanTarget, ".git"+string(filepath.Separator)) {
			return fmt.Errorf("security violation: refusing to inject into .git directory (%s)", targetRel)
		}

		destPath, err := shadowGuard.ValidateRelativePath(cleanTarget)
		if err != nil {
			return fmt.Errorf("security violation: invalid inject destination %q: %w", targetRel, err)
		}

		resolvedSrc, err := resolveSourcePath(s.baseDir, srcPath)
		if err != nil {
			return err
		}

		srcFi, err := os.Stat(resolvedSrc)
		if err != nil {
			return fmt.Errorf("injected source file not found: %s: %w", resolvedSrc, err)
		}
		if srcFi.IsDir() {
			return fmt.Errorf("injected source %q is a directory, only regular files supported", resolvedSrc)
		}

		const maxInjectedFileSize = 50 * 1024 * 1024 // 50MB
		if srcFi.Size() > maxInjectedFileSize {
			return fmt.Errorf("injected source file %q exceeds 50MB limit (%d bytes)", resolvedSrc, srcFi.Size())
		}

		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			return fmt.Errorf("failed to create directory for injected file %q: %w", targetRel, err)
		}

		if err := SafeCopyFile(resolvedSrc, destPath, maxInjectedFileSize); err != nil {
			return fmt.Errorf("failed to inject %q from %q: %w", targetRel, resolvedSrc, err)
		}

		s.injectedFiles = append(s.injectedFiles, cleanTarget)
	}

	return nil
}

func (s *GitWorktreeSession) CaptureDiff(ctx context.Context) (*DiffReport, error) {
	report := &DiffReport{
		SessionID:     s.id,
		GeneratedAt:   time.Now(),
		FilesAdded:    make([]string, 0),
		FilesModified: make([]string, 0),
		FilesDeleted:  make([]string, 0),
	}

	if isGitRepo(s.shadowDir) {
		// Use -z (NUL-delimited, unquoted) so leading spaces on unstaged statuses (" M foo.go")
		// are never stripped and filenames with spaces or special characters are preserved verbatim.
		cmd := exec.CommandContext(ctx, "git", "-c", "core.quotepath=false", "status", "--porcelain", "-uall", "-z")
		cmd.Dir = s.shadowDir
		output, err := cmd.Output()
		if err == nil && len(output) > 0 {
			entries := bytes.Split(output, []byte{0})
			for i := 0; i < len(entries); i++ {
				entry := string(entries[i])
				if len(entry) < 4 || entry[2] != ' ' {
					continue
				}
				status := entry[:2]
				file := filepath.FromSlash(entry[3:])
				// In -z mode, rename/copy entries emit an extra NUL-terminated original path right after new path.
				if strings.ContainsRune(status, 'R') || strings.ContainsRune(status, 'C') {
					if i+1 < len(entries) {
						i++
					}
				}
				if s.shouldExcludeFromSync(file) {
					continue
				}
				switch {
				case strings.Contains(status, "?") || strings.Contains(status, "A"):
					report.FilesAdded = append(report.FilesAdded, file)
				case strings.Contains(status, "M") || strings.Contains(status, "R") || strings.Contains(status, "C") || strings.Contains(status, "T"):
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
	} else {
		// Non-git filesystem diff comparison against base directory
		_ = filepath.Walk(s.shadowDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			rel, rErr := filepath.Rel(s.shadowDir, path)
			if rErr != nil || rel == "." {
				return nil
			}
			if s.shouldExcludeFromSync(rel) {
				if info.IsDir() && (rel == ".git" || strings.HasPrefix(rel, ".git"+string(filepath.Separator))) {
					return filepath.SkipDir
				}
				return nil
			}
			if info.IsDir() {
				return nil
			}
			basePath := filepath.Join(s.baseDir, rel)
			baseFi, statErr := os.Lstat(basePath)
			if os.IsNotExist(statErr) {
				report.FilesAdded = append(report.FilesAdded, rel)
			} else if statErr == nil {
				if baseFi.Size() != info.Size() || !baseFi.ModTime().Equal(info.ModTime()) || (info.Mode()&os.ModeSymlink != 0) {
					report.FilesModified = append(report.FilesModified, rel)
				}
			}
			return nil
		})
		_ = filepath.Walk(s.baseDir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			rel, rErr := filepath.Rel(s.baseDir, path)
			if rErr != nil || s.shouldExcludeFromSync(rel) {
				return nil
			}
			shadowPath := filepath.Join(s.shadowDir, rel)
			if _, statErr := os.Lstat(shadowPath); os.IsNotExist(statErr) {
				report.FilesDeleted = append(report.FilesDeleted, rel)
			}
			return nil
		})
	}

	return report, nil
}

// ApplyToHost enforces SemanticDiffAuditor checks and safely copies validated changes back to the host workspace.
func (s *GitWorktreeSession) ApplyToHost(ctx context.Context) error {
	return s.applyToHost(ctx, false)
}

// ApplyToHostForceUnvetted applies changes when an interactive human CLI operator explicitly passes --force-unvetted.
func (s *GitWorktreeSession) ApplyToHostForceUnvetted(ctx context.Context) error {
	return s.applyToHost(ctx, true)
}

func (s *GitWorktreeSession) applyToHost(ctx context.Context, forceUnvetted bool) error {
	diff, err := s.CaptureDiff(ctx)
	if err != nil {
		return fmt.Errorf("failed to capture diff: %w", err)
	}

	shadowGuard, err := NewSafePathGuard(s.shadowDir)
	if err != nil {
		return fmt.Errorf("failed to initialize shadow path guard: %w", err)
	}
	hostGuard, err := NewSafePathGuard(s.baseDir)
	if err != nil {
		return fmt.Errorf("failed to initialize host path guard: %w", err)
	}

	allChanged := append(diff.FilesAdded, diff.FilesModified...)
	if len(allChanged) > 1000 {
		return fmt.Errorf("%w: total files modified (%d) exceeds limit of 1000", ErrQuotaExceeded, len(allChanged))
	}

	candidates := make([]string, 0, len(allChanged))
	for _, rel := range allChanged {
		if s.shouldExcludeFromSync(rel) {
			continue
		}

		// Verify source does not escape shadow workspace and has no intermediate or leaf symlinks
		isSymlink, inspectErr := shadowGuard.InspectFile(rel)
		if inspectErr != nil {
			return fmt.Errorf("security violation: refusing to copy %q: %w", rel, inspectErr)
		}
		if isSymlink {
			return fmt.Errorf("security violation: refusing to copy symlink %q to host workspace: %w", rel, ErrIllegalSymlinkTarget)
		}

		if _, vErr := shadowGuard.ValidateRelativePath(rel); vErr != nil {
			return fmt.Errorf("invalid source path %q: %w", rel, vErr)
		}
		if _, vErr := hostGuard.ValidateRelativePath(rel); vErr != nil {
			return fmt.Errorf("invalid destination path %q: %w", rel, vErr)
		}

		candidates = append(candidates, rel)
	}

	// Enforce SemanticDiffAuditor directly inside ApplyToHost so MCP or programmatic callers cannot bypass it
	if len(candidates) > 0 {
		auditor := argus.NewSemanticDiffAuditor(s.baseDir)
		auditReport, auditErr := auditor.AuditFiles(ctx, s.shadowDir, candidates)
		if auditErr != nil {
			return fmt.Errorf("semantic diff audit failed: %w", auditErr)
		}
		if !auditReport.Allowed && !forceUnvetted {
			first := auditReport.Findings[0]
			return fmt.Errorf("%w: [%s] %s: %s", ErrDiffAuditBlocked, first.Severity, first.File, first.Description)
		}
	}

	const maxFileBytes = 50 * 1024 * 1024
	for _, rel := range candidates {
		src, vErr := shadowGuard.ValidateRelativePath(rel)
		if vErr != nil {
			return fmt.Errorf("invalid source path %q: %w", rel, vErr)
		}
		srcFi, statErr := os.Lstat(src)
		if statErr != nil {
			continue
		}
		if srcFi.IsDir() {
			continue
		}

		if copyErr := SafeCopyBetweenRoots(s.shadowDir, s.baseDir, rel, maxFileBytes); copyErr != nil {
			return fmt.Errorf("failed to safely write %q to host workspace: %w", rel, copyErr)
		}
	}

	return nil
}

func (s *GitWorktreeSession) Cleanup(ctx context.Context) error {
	// Restore write permissions on masked directories inside shadowDir so RemoveAll succeeds cleanly
	for _, rel := range s.maskedPaths {
		p := filepath.Join(s.shadowDir, rel)
		if fi, err := os.Lstat(p); err == nil && fi.IsDir() {
			if chmodErr := os.Chmod(p, 0700); chmodErr != nil {
				// Best-effort cleanup unlock
			}
		}
	}

	if s.branchName != "" && isGitRepo(s.baseDir) {
		cmd := exec.CommandContext(ctx, "git", "worktree", "remove", "--force", s.shadowDir)
		cmd.Dir = s.baseDir
		if err := cmd.Run(); err != nil {
			// Non-fatal if worktree was already detached
		}

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
	_, err := os.Stat(gitDir)
	return err == nil
}

func copyDirectory(src, dst string) error {
	if err := os.MkdirAll(dst, 0755); err != nil {
		return err
	}
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if rel == ".git" || strings.HasPrefix(rel, ".git"+string(filepath.Separator)) ||
			rel == "build" || strings.HasPrefix(rel, "build"+string(filepath.Separator)) ||
			rel == "dist" || strings.HasPrefix(rel, "dist"+string(filepath.Separator)) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, info.Mode())
		}

		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}

		if info.Mode()&os.ModeSymlink != 0 {
			linkTarget, err := os.Readlink(path)
			if err != nil {
				return nil
			}
			if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
				return nil
			}
			return os.Symlink(linkTarget, target)
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		return os.WriteFile(target, data, info.Mode())
	})
}
