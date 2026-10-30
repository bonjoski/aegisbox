//go:build windows

package main

import (
	"os/exec"
)

func setProcessGroup(cmd *exec.Cmd) {
	// Process groups not supported in same manner on Windows
}
