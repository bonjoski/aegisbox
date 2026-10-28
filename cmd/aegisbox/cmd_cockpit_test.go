package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestFindAegisboxCockpit_FromPATH(t *testing.T) {
	tempDir := t.TempDir()
	binName := "aegisbox-cockpit"
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}
	fakeBinary := filepath.Join(tempDir, binName)
	if err := os.WriteFile(fakeBinary, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatalf("failed to create fake binary: %v", err)
	}

	origPath := os.Getenv("PATH")
	os.Setenv("PATH", tempDir+string(os.PathListSeparator)+origPath)
	defer os.Setenv("PATH", origPath)

	path, isApp, err := findAegisboxCockpit()
	if err != nil {
		t.Fatalf("expected binary to be found on PATH, got error: %v", err)
	}
	if filepath.Clean(path) != filepath.Clean(fakeBinary) {
		t.Errorf("expected %q, got %q", fakeBinary, path)
	}
	if isApp {
		t.Errorf("expected isApp to be false for PATH binary")
	}
}

func TestFindAegisboxCockpit_NotFound(t *testing.T) {
	tempDir := t.TempDir()
	origPath := os.Getenv("PATH")
	os.Setenv("PATH", tempDir)
	defer os.Setenv("PATH", origPath)

	// In an isolated empty PATH and working directory without bin/
	currDir, _ := os.Getwd()
	os.Chdir(tempDir)
	defer os.Chdir(currDir)

	_, _, err := findAegisboxCockpit()
	if err == nil {
		t.Errorf("expected error when cockpit binary is missing")
	}
}
