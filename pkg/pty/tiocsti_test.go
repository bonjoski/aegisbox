package pty

import (
	"os"
	"testing"
)

func TestCheckTIOCSTI_NonTerminalFile(t *testing.T) {
	if os.Getenv("OS") == "Windows_NT" || os.PathSeparator == '\\' {
		t.Skip("TIOCSTI ioctl is a Unix-specific vector, skipped on Windows")
	}
	tmp, err := os.CreateTemp("", "tiocsti-test")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	err = CheckTIOCSTI(tmp)
	if err == nil {
		t.Fatal("expected TIOCSTI on regular file to return error, got nil")
	}
}

func TestCheckTIOCSTI_NilFile(t *testing.T) {
	if os.Getenv("OS") == "Windows_NT" || os.PathSeparator == '\\' {
		t.Skip("TIOCSTI ioctl is a Unix-specific vector, skipped on Windows")
	}
	err := CheckTIOCSTI(nil)
	if err == nil {
		t.Fatal("expected error on nil file, got nil")
	}
}

func TestIsTerminal_RegularFile(t *testing.T) {
	tmp, err := os.CreateTemp("", "pty-term-test")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	d := NewDetector()
	if d.IsTerminal(tmp) {
		t.Errorf("expected regular file not to be identified as terminal")
	}
	if d.IsTerminal(nil) {
		t.Errorf("expected nil file not to be identified as terminal")
	}
}
