package policy

import "strings"

// IsDangerousEnvVar checks for dangerous dynamic linker or interpreter hijacking variables.
func IsDangerousEnvVar(name string) bool {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT",
		"DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH",
		"BASH_ENV", "ENV", "CDPATH", "IFS", "SHELLOPTS", "BASHOPTS", "PROMPT_COMMAND",
		"NODE_OPTIONS", "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP",
		"PERL5OPT", "PERL5LIB", "RUBYOPT", "RUBYLIB", "LUA_PATH", "LUA_CPATH":
		return true
	default:
		return false
	}
}
