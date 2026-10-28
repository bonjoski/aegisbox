package policy

import (
	"fmt"
	"strings"
)

// Standard Profile Names
const (
	ProfileStandard = "standard"
	ProfileGo       = "go"
	ProfileRust     = "rust"
	ProfileNode     = "node"
	ProfilePython   = "python"
	ProfileStrict   = "strict"
	ProfileAirgap   = "airgap"
)

// StandardRegistryDomains lists essential registries and repositories
// for modern multi-language developer runtimes.
var StandardRegistryDomains = []string{
	// Go
	"proxy.golang.org",
	"sum.golang.org",
	"pkg.go.dev",
	// Rust
	"crates.io",
	"static.crates.io",
	"index.crates.io",
	// Node
	"registry.npmjs.org",
	"registry.yarnpkg.com",
	// Python
	"pypi.org",
	"files.pythonhosted.org",
	"pypi.python.org",
	// Java / Maven / Gradle
	"repo.maven.apache.org",
	"repo1.maven.org",
	"plugins.gradle.org",
	// .NET / NuGet
	"api.nuget.org",
	"nuget.org",
	// Ruby
	"rubygems.org",
	"index.rubygems.org",
	// Swift / CocoaPods
	"cdn.cocoapods.org",
	// Container / OCI Registries & Helm
	"docker.io",
	"registry-1.docker.io",
	"ghcr.io",
	"quay.io",
	"gcr.io",
	// VCS / GitHub
	"github.com",
	"api.github.com",
	"raw.githubusercontent.com",
	"objects.githubusercontent.com",
}

// GoRegistryDomains contains Go module proxy and VCS endpoints.
var GoRegistryDomains = []string{
	"proxy.golang.org",
	"sum.golang.org",
	"pkg.go.dev",
	"github.com",
	"api.github.com",
	"raw.githubusercontent.com",
}

// RustRegistryDomains contains Cargo / Crates.io endpoints.
var RustRegistryDomains = []string{
	"crates.io",
	"static.crates.io",
	"index.crates.io",
	"github.com",
	"api.github.com",
	"raw.githubusercontent.com",
}

// NodeRegistryDomains contains NPM and Yarn registries.
var NodeRegistryDomains = []string{
	"registry.npmjs.org",
	"registry.yarnpkg.com",
	"github.com",
	"api.github.com",
	"raw.githubusercontent.com",
}

// PythonRegistryDomains contains PyPI and warehouse CDN endpoints.
var PythonRegistryDomains = []string{
	"pypi.org",
	"files.pythonhosted.org",
	"pypi.python.org",
	"github.com",
	"api.github.com",
	"raw.githubusercontent.com",
}

// StrictRegistryDomains allows strictly VCS repository fetch.
var StrictRegistryDomains = []string{
	"github.com",
	"api.github.com",
}

// ResolveProfileDomains resolves a named runtime profile into allowed network domains.
func ResolveProfileDomains(profile string) ([]string, error) {
	switch strings.ToLower(strings.TrimSpace(profile)) {
	case "", ProfileStandard:
		return StandardRegistryDomains, nil
	case ProfileGo:
		return GoRegistryDomains, nil
	case ProfileRust:
		return RustRegistryDomains, nil
	case ProfileNode:
		return NodeRegistryDomains, nil
	case ProfilePython:
		return PythonRegistryDomains, nil
	case ProfileStrict:
		return StrictRegistryDomains, nil
	case ProfileAirgap:
		return []string{}, nil
	default:
		return nil, fmt.Errorf("unknown network profile %q (valid: standard, go, rust, node, python, strict, airgap)", profile)
	}
}
