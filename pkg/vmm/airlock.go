package vmm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// AirlockOpts defines parameters passed to the Airlock execution tier.
type AirlockOpts struct {
	WorkspaceRoot  string
	WorkingDir     string
	Airgap         bool
	Profile        string
	AllowedDomains []string
	Interactive    bool
	Stdin          io.Reader
	Stdout         io.Writer
	Stderr         io.Writer
}

// DiscoverAirlock locates the Airlock binary on the host workstation.
func DiscoverAirlock() (string, error) {
	if p := os.Getenv("AIRLOCK_PATH"); p != "" {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p, nil
		}
		return "", fmt.Errorf("airlock binary specified in AIRLOCK_PATH %q not found or not executable", p)
	}

	if p, err := exec.LookPath("airlock"); err == nil {
		return p, nil
	}

	home, _ := os.UserHomeDir()
	candidates := []string{
		"/usr/local/bin/airlock",
		"/opt/homebrew/bin/airlock",
		filepath.Join(home, ".local", "bin", "airlock"),
		filepath.Join(home, "bin", "airlock"),
		filepath.Join(home, "go", "bin", "airlock"),
		filepath.Join(home, ".airlock", "bin", "airlock"),
		"/Users/benskolmoski/supplychain/airlock/bin/airlock",
	}

	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			return c, nil
		}
	}

	return "", errors.New("airlock binary not found on PATH or standard install locations (set AIRLOCK_PATH to override or install via 'brew install bonjoski/tap/airlock')")
}

// ExecuteAirlock delegates sandboxed execution to Airlock.
func ExecuteAirlock(ctx context.Context, opts AirlockOpts, cmdArgs []string) (int, error) {
	bin, err := DiscoverAirlock()
	if err != nil {
		return 1, fmt.Errorf("airlock engine: %w", err)
	}

	var args []string

	if opts.Airgap {
		args = append(args, "--airgap")
	} else if opts.Profile != "" {
		args = append(args, "--profile", opts.Profile)
	}

	if len(opts.AllowedDomains) > 0 {
		args = append(args, "--allow", strings.Join(opts.AllowedDomains, ","))
	}

	args = append(args, cmdArgs...)

	cmd := exec.CommandContext(ctx, bin, args...)
	if opts.WorkingDir != "" {
		cmd.Dir = opts.WorkingDir
	} else if opts.WorkspaceRoot != "" {
		cmd.Dir = opts.WorkspaceRoot
	}

	cmd.Stdin = opts.Stdin
	cmd.Stdout = opts.Stdout
	cmd.Stderr = opts.Stderr

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode(), nil
		}
		return 1, err
	}

	return 0, nil
}
