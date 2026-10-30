package shim

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOverlayShim_MountAndRollback(t *testing.T) {
	tempDir := t.TempDir()
	lowerDir := filepath.Join(tempDir, "lower_workspace")
	if err := os.MkdirAll(lowerDir, 0755); err != nil {
		t.Fatalf("Failed to create lower dir: %v", err)
	}

	// Populate base workspace files
	files := map[string]string{
		"package.json": `{"name": "test-project", "version": "1.0.0"}`,
		"src/index.js":  `console.log("hello world");`,
	}
	for path, content := range files {
		fullPath := filepath.Join(lowerDir, path)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
			t.Fatalf("Failed to create parent dir: %v", err)
		}
		if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to write initial file: %v", err)
		}
	}

	cfg := OverlayConfig{
		LowerDir: lowerDir,
	}

	shim, err := NewOverlayShim(cfg)
	if err != nil {
		t.Fatalf("NewOverlayShim failed: %v", err)
	}
	defer shim.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := shim.Mount(ctx); err != nil {
		t.Fatalf("Mount failed: %v", err)
	}

	if !shim.IsMounted() {
		t.Fatal("Expected shim to report IsMounted == true")
	}

	mountPoint := shim.MountPoint()
	if mountPoint == "" {
		t.Fatal("Expected non-empty mountpoint")
	}

	// 1. Verify read access to base files
	basePkg := filepath.Join(mountPoint, "package.json")
	if data, err := os.ReadFile(basePkg); err != nil || string(data) != files["package.json"] {
		t.Fatalf("Failed to read base file from mountpoint: %v", err)
	}

	// 2. Perform build writes (node_modules, target artifacts) in mountpoint
	buildFiles := map[string]string{
		"node_modules/dummy/index.js": `module.exports = {};`,
		"dist/bundle.js":              `// bundled code`,
		"target/release/binary":       `ELF_BINARY_DATA`,
	}
	for path, content := range buildFiles {
		fullPath := filepath.Join(mountPoint, path)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
			t.Fatalf("Failed to create build dir: %v", err)
		}
		if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to write build artifact: %v", err)
		}
	}

	// 3. Verify lower directory remains 100% clean and isolated
	for path := range buildFiles {
		lowerPath := filepath.Join(lowerDir, path)
		if _, err := os.Stat(lowerPath); !os.IsNotExist(err) {
			t.Fatalf("Adversarial Leak! Build file %q leaked into lower directory", path)
		}
	}

	// 4. Test Instant Rollback (< 5ms)
	rollbackStart := time.Now()
	if err := shim.Rollback(ctx); err != nil {
		t.Fatalf("Rollback failed: %v", err)
	}
	rollbackDuration := time.Since(rollbackStart)
	t.Logf("Instant rollback completed in %v", rollbackDuration)

	if rollbackDuration > 50*time.Millisecond {
		t.Errorf("Rollback took %v, expected < 50ms", rollbackDuration)
	}

	if shim.IsMounted() {
		t.Fatal("Expected shim to report IsMounted == false after rollback")
	}

	// 5. Verify lower directory is completely intact
	for path, expectedContent := range files {
		lowerPath := filepath.Join(lowerDir, path)
		data, err := os.ReadFile(lowerPath)
		if err != nil {
			t.Fatalf("Expected lower file %q to exist after rollback: %v", path, err)
		}
		if string(data) != expectedContent {
			t.Fatalf("Lower file %q was corrupted! Expected %q, got %q", path, expectedContent, string(data))
		}
	}
}

func TestOverlayShim_Commit(t *testing.T) {
	tempDir := t.TempDir()
	lowerDir := filepath.Join(tempDir, "lower")
	targetDir := filepath.Join(tempDir, "promoted_target")
	_ = os.MkdirAll(lowerDir, 0755)
	_ = os.MkdirAll(targetDir, 0755)

	_ = os.WriteFile(filepath.Join(lowerDir, "base.txt"), []byte("base-content"), 0644)

	shim, err := NewOverlayShim(OverlayConfig{LowerDir: lowerDir})
	if err != nil {
		t.Fatalf("NewOverlayShim failed: %v", err)
	}
	defer shim.Close()

	ctx := context.Background()
	if err := shim.Mount(ctx); err != nil {
		t.Fatalf("Mount failed: %v", err)
	}

	// Write new file in mountpoint
	newFile := filepath.Join(shim.MountPoint(), "approved_patch.go")
	if err := os.WriteFile(newFile, []byte("package main"), 0644); err != nil {
		t.Fatalf("Failed to write approved patch: %v", err)
	}

	// Commit to target
	if err := shim.Commit(ctx, targetDir); err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	// Verify committed file exists in targetDir
	promoted := filepath.Join(targetDir, "approved_patch.go")
	data, err := os.ReadFile(promoted)
	if err != nil || string(data) != "package main" {
		t.Fatalf("Failed to verify committed file in target: %v", err)
	}
}

func TestOverlayShim_SubtreeTargets(t *testing.T) {
	tempDir := t.TempDir()
	lowerDir := filepath.Join(tempDir, "workspace")
	_ = os.MkdirAll(lowerDir, 0755)
	_ = os.WriteFile(filepath.Join(lowerDir, "Cargo.toml"), []byte("[package]"), 0644)

	cfg := OverlayConfig{
		LowerDir:       lowerDir,
		SubtreeTargets: []string{"target", "node_modules"},
	}

	mgr, err := NewOverlayShim(cfg)
	if err != nil {
		t.Fatalf("NewOverlayShim with subtree targets failed: %v", err)
	}
	defer mgr.Close()

	ctx := context.Background()
	if err := mgr.Mount(ctx); err != nil {
		t.Fatalf("Mount subtrees failed: %v", err)
	}

	if len(mgr.SubtreeShims()) != 2 {
		t.Fatalf("Expected 2 sub-shims, got %d", len(mgr.SubtreeShims()))
	}

	if err := mgr.Rollback(ctx); err != nil {
		t.Fatalf("Rollback subtrees failed: %v", err)
	}
}

func TestOverlayShim_ValidationErrors(t *testing.T) {
	// Empty lowerdir
	_, err := NewOverlayShim(OverlayConfig{LowerDir: ""})
	if err != ErrLowerDirRequired {
		t.Errorf("Expected ErrLowerDirRequired, got %v", err)
	}

	// Non-existent lowerdir
	_, err = NewOverlayShim(OverlayConfig{LowerDir: "/path/does/not/exist/at/all"})
	if err == nil {
		t.Error("Expected error for non-existent lowerdir, got nil")
	}

	// Double mount
	validDir := t.TempDir()
	shim, err := NewOverlayShim(OverlayConfig{LowerDir: validDir})
	if err != nil {
		t.Fatalf("NewOverlayShim failed: %v", err)
	}
	defer shim.Close()

	ctx := context.Background()
	if err := shim.Mount(ctx); err != nil {
		t.Fatalf("Mount failed: %v", err)
	}

	if err := shim.Mount(ctx); err != ErrAlreadyMounted {
		t.Errorf("Expected ErrAlreadyMounted on second mount, got %v", err)
	}
}
