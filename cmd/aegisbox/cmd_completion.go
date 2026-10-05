package main

import (
	"context"
	"fmt"
	"strings"
)

func runCompletion(ctx context.Context, args []string) error {
	shell := "bash"
	if len(args) > 0 {
		shell = strings.ToLower(args[0])
	}

	switch shell {
	case "bash":
		fmt.Print(bashCompletionScript)
	case "zsh":
		fmt.Print(zshCompletionScript)
	case "fish":
		fmt.Print(fishCompletionScript)
	default:
		return fmt.Errorf("unsupported shell %q (supported: bash, zsh, fish)", shell)
	}

	return nil
}

const bashCompletionScript = `#!/usr/bin/env bash
# Aegisbox Bash Completion

_aegisbox_completion() {
    local cur prev subcommands
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    subcommands="doctor vet exec range benchmark matrix monitor diff mcp version completion"

    if [ "$COMP_CWORD" -eq 1 ]; then
        COMPREPLY=( $(compgen -W "${subcommands}" -- "$cur") )
        return 0
    fi

    case "$prev" in
        exec)
            COMPREPLY=( $(compgen -W "--apply --skip-vet --engine=local --engine=microvm --mask" -- "$cur") )
            ;;
        range)
            COMPREPLY=( $(compgen -W "--target --canary" -- "$cur") )
            ;;
        benchmark)
            COMPREPLY=( $(compgen -W "--concurrency --strict --json --output" -- "$cur") )
            ;;
        matrix)
            COMPREPLY=( $(compgen -W "--manifest --concurrency --format --output --sample" -- "$cur") )
            ;;
        monitor)
            COMPREPLY=( $(compgen -W "--demo --session" -- "$cur") )
            ;;
        mcp)
            COMPREPLY=( $(compgen -W "config" -- "$cur") )
            ;;
        completion)
            COMPREPLY=( $(compgen -W "bash zsh fish" -- "$cur") )
            ;;
        *)
            COMPREPLY=()
            ;;
    esac
}

complete -F _aegisbox_completion aegisbox
`

const zshCompletionScript = `#compdef aegisbox

_aegisbox() {
    local -a subcommands
    subcommands=(
        'doctor:Run diagnostic environment checks'
        'vet:Perform pre-flight AST analysis and package slopsquatting check'
        'exec:Execute a command inside an ephemeral shadowed CoW workspace'
        'range:Run an adversarial task pinned to a target host with canary tripwires'
        'benchmark:Run adversarial red-team benchmark evaluation suite'
        'matrix:Run parallel multi-agent evaluation matrix across isolated shadow worktrees'
        'monitor:Launch real-time security telemetry and MicroVM resource monitor'
        'diff:Inspect or apply workspace changes made during an aegisbox session'
        'mcp:Start or configure Model Context Protocol server for IDE agents'
        'version:Show aegisbox version information'
        'completion:Generate shell autocompletion script'
    )

    if (( CURRENT == 2 )); then
        _describe -t subcommands 'aegisbox commands' subcommands
    fi
}

_aegisbox "$@"
`

const fishCompletionScript = `# Aegisbox Fish Completion

complete -c aegisbox -f
complete -c aegisbox -n "__fish_use_subcommand" -a doctor -d "Run diagnostic environment checks"
complete -c aegisbox -n "__fish_use_subcommand" -a vet -d "Perform pre-flight AST analysis and package slopsquatting check"
complete -c aegisbox -n "__fish_use_subcommand" -a exec -d "Execute inside an ephemeral shadowed workspace"
complete -c aegisbox -n "__fish_use_subcommand" -a range -d "Run an adversarial task pinned to target host with canary tripwires"
complete -c aegisbox -n "__fish_use_subcommand" -a benchmark -d "Run adversarial red-team benchmark suite"
complete -c aegisbox -n "__fish_use_subcommand" -a matrix -d "Run parallel multi-agent evaluation matrix"
complete -c aegisbox -n "__fish_use_subcommand" -a monitor -d "Launch real-time security telemetry monitor"
complete -c aegisbox -n "__fish_use_subcommand" -a diff -d "Inspect or apply workspace changes"
complete -c aegisbox -n "__fish_use_subcommand" -a mcp -d "Start or configure Model Context Protocol server"
complete -c aegisbox -n "__fish_use_subcommand" -a version -d "Show version information"
complete -c aegisbox -n "__fish_use_subcommand" -a completion -d "Generate shell completion script"
`
