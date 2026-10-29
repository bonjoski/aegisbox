package workspace

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var (
	// ErrSymlinkRejected is returned when an untrusted symlink is detected in staging cache.
	ErrSymlinkRejected = errors.New("cache: untrusted symlink detected in cache staging layer")
	// ErrPathTraversal is returned when an invalid path traversal attempt is detected.
	ErrPathTraversal = errors.New("cache: illegal path traversal attempt in staging file")
)

// CacheMount describes a host directory to bind into the sandbox read-only.
type CacheMount struct {
	HostPath string
	ReadOnly bool
}

// ToolCacheMapping links a package manager cache name to its default host path and staging subdir.
type ToolCacheMapping struct {
	Name        string
	Subdir      string
	HostRelPath string // Relative to userHome
	EnvVar      string
}

// DefaultToolMappings returns standard package manager cache definitions.
func DefaultToolMappings() []ToolCacheMapping {
	return []ToolCacheMapping{
		{
			Name:        "npm",
			Subdir:      "npm",
			HostRelPath: ".npm",
			EnvVar:      "npm_config_cache",
		},
		{
			Name:        "yarn",
			Subdir:      "yarn",
			HostRelPath: filepath.Join(".cache", "yarn"),
			EnvVar:      "YARN_CACHE_FOLDER",
		},
		{
			Name:        "pnpm",
			Subdir:      "pnpm",
			HostRelPath: filepath.Join(".local", "share", "pnpm", "store"),
			EnvVar:      "",
		},
		{
			Name:        "pip",
			Subdir:      "pip",
			HostRelPath: filepath.Join(".cache", "pip"),
			EnvVar:      "PIP_CACHE_DIR",
		},
		{
			Name:        "uv",
			Subdir:      "uv",
			HostRelPath: filepath.Join(".cache", "uv"),
			EnvVar:      "UV_CACHE_DIR",
		},
		{
			Name:        "cargo-registry",
			Subdir:      "cargo-registry",
			HostRelPath: filepath.Join(".cargo", "registry"),
			EnvVar:      "",
		},
		{
			Name:        "cargo-git",
			Subdir:      "cargo-git",
			HostRelPath: filepath.Join(".cargo", "git"),
			EnvVar:      "",
		},
		{
			Name:        "go-mod",
			Subdir:      "go-mod",
			HostRelPath: filepath.Join("go", "pkg", "mod"),
			EnvVar:      "GOMODCACHE",
		},
		{
			Name:        "go-build",
			Subdir:      "go-build",
			HostRelPath: filepath.Join(".cache", "go-build"),
			EnvVar:      "GOCACHE",
		},
	}
}

// StagingConfig contains provisioned paths and environment variables for sandboxed processes.
type StagingConfig struct {
	BaseDir string
	EnvVars map[string]string
}

// CacheManager manages host cache discovery and safe staging overlays.
type CacheManager struct {
	mappings []ToolCacheMapping
}

// NewCacheManager creates a new CacheManager with standard tool mappings.
func NewCacheManager() *CacheManager {
	return &CacheManager{
		mappings: DefaultToolMappings(),
	}
}

// GetHostCacheMounts returns the existing host cache directories to mount read-only.
func (m *CacheManager) GetHostCacheMounts(userHome string) []CacheMount {
	var mounts []CacheMount
	if userHome == "" {
		return mounts
	}

	for _, t := range m.mappings {
		hostPath := filepath.Join(userHome, t.HostRelPath)
		if fi, err := os.Stat(hostPath); err == nil && fi.IsDir() {
			mounts = append(mounts, CacheMount{
				HostPath: hostPath,
				ReadOnly: true,
			})
		}
	}
	return mounts
}

// ProvisionStaging creates isolated staging directories and returns redirection environment variables.
func (m *CacheManager) ProvisionStaging(stagingBase string) (*StagingConfig, error) {
	if stagingBase == "" {
		return nil, errors.New("cache: staging base path cannot be empty")
	}

	if err := os.MkdirAll(stagingBase, 0700); err != nil {
		return nil, fmt.Errorf("cache: failed to create staging directory %q: %w", stagingBase, err)
	}

	envVars := make(map[string]string)

	for _, t := range m.mappings {
		subdirPath := filepath.Join(stagingBase, t.Subdir)
		if err := os.MkdirAll(subdirPath, 0700); err != nil {
			return nil, fmt.Errorf("cache: failed to create cache subdir %q: %w", subdirPath, err)
		}
		if t.EnvVar != "" {
			envVars[t.EnvVar] = subdirPath
		}
	}

	return &StagingConfig{
		BaseDir: stagingBase,
		EnvVars: envVars,
	}, nil
}

// SyncBack copies safe downloaded artifacts from the staging directory back to host caches.
// Symlinks are strictly refused to prevent malicious cache poisoning escapes.
func (m *CacheManager) SyncBack(stagingBase, userHome string) error {
	if stagingBase == "" || userHome == "" {
		return nil
	}

	cleanUserHome := filepath.Clean(userHome)

	for _, t := range m.mappings {
		stagingSubdir := filepath.Join(stagingBase, t.Subdir)
		if _, err := os.Stat(stagingSubdir); os.IsNotExist(err) {
			continue
		}

		targetHostDir := filepath.Join(cleanUserHome, t.HostRelPath)

		err := filepath.Walk(stagingSubdir, func(path string, info os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}

			if path == stagingSubdir {
				return nil
			}

			// Reject any symlinks to eliminate cache poisoning traversal
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("%w: %s", ErrSymlinkRejected, path)
			}

			rel, err := filepath.Rel(stagingSubdir, path)
			if err != nil {
				return err
			}

			destPath := filepath.Join(targetHostDir, rel)
			cleanDest := filepath.Clean(destPath)

			// Path traversal check: verify destination is strictly contained within targetHostDir
			relDest, err := filepath.Rel(targetHostDir, cleanDest)
			if err != nil || strings.HasPrefix(relDest, "..") || filepath.IsAbs(relDest) {
				return fmt.Errorf("%w: %s", ErrPathTraversal, destPath)
			}

			if info.IsDir() {
				return os.MkdirAll(cleanDest, 0755)
			}

			// Only copy if the destination does not already exist
			if _, err := os.Stat(cleanDest); err == nil {
				return nil // Don't overwrite existing host cache entries
			}

			if err := os.MkdirAll(filepath.Dir(cleanDest), 0755); err != nil {
				return err
			}

			_, err = copyFileContents(path, cleanDest, 0644)
			return err
		})

		if err != nil {
			return fmt.Errorf("cache sync failed for %s: %w", t.Name, err)
		}
	}

	return nil
}
