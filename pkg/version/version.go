package version

import (
	"fmt"
	"runtime"
)

// Current is the single canonical source of truth for Aegisbox semantic version.
const Current = "0.3.0"

// Version is the active semantic version, can be overridden via ldflags at build time.
var Version = Current

// GitCommit can be populated via build ldflags: -X github.com/bonjoski/aegisbox/pkg/version.GitCommit=...
var GitCommit = ""

// BuildDate can be populated via build ldflags: -X github.com/bonjoski/aegisbox/pkg/version.BuildDate=...
var BuildDate = ""

// Full returns a descriptive version string.
func Full() string {
	if GitCommit != "" {
		return fmt.Sprintf("aegisbox version %s (%s, %s/%s)", Version, GitCommit, runtime.GOOS, runtime.GOARCH)
	}
	return fmt.Sprintf("aegisbox version %s", Version)
}
