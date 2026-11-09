package mcp

import (
	"context"
	"fmt"
	"sync"

	"cel.dev/cel-go/cel"
)

// Rule defines a single declarative security policy rule.
type Rule struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	Expression  string   `json:"expression"`
	Action      Decision `json:"action"` // "ALLOW", "INTERCEPT_APPROVAL", "DENY"
	Severity    string   `json:"severity"`
	program     cel.Program
}

// CELPolicyEngine compiles and evaluates CEL expressions against MCP tool call ASTs.
type CELPolicyEngine struct {
	env   *cel.Env
	rules []*Rule
	mu    sync.RWMutex
}

// NewCELPolicyEngine initializes a policy engine with the standard Aegisbox rule environment.
func NewCELPolicyEngine() (*CELPolicyEngine, error) {
	env, err := cel.NewEnv(
		cel.Variable("tool", cel.StringType),
		cel.Variable("args", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("workspace", cel.StringType),
		cel.Variable("profile", cel.StringType),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL environment: %w", err)
	}

	engine := &CELPolicyEngine{
		env: env,
	}

	if err := engine.loadDefaultRules(); err != nil {
		return nil, err
	}

	return engine, nil
}

func (e *CELPolicyEngine) loadDefaultRules() error {
	defaults := []*Rule{
		{
			ID:          "rule-deny-destructive-disk",
			Description: "Deny destructive disk erasure commands (multiline-hardened)",
			Expression:  `(tool == "run_command" || tool == "aegisbox_exec") && has(args.command) && (args.command.matches("(?s).*(rm\\s+-rf\\s+[/~]|dd\\s+if=).*") || args.command.matches("(?s).*mkfs.*"))`,
			Action:      DecisionDeny,
			Severity:    "CRITICAL",
		},
		{
			ID:          "rule-intercept-credentials",
			Description: "Intercept sensitive credentials and SSH key access (multiline-hardened)",
			Expression:  `tool == "read_file" && has(args.path) && (args.path.matches("(?s).*(\\.env|id_rsa|\\.aws|\\.kube|credentials).*") || args.path.startsWith("/etc/"))`,
			Action:      DecisionInterceptApproval,
			Severity:    "HIGH",
		},
		{
			ID:          "rule-intercept-unvetted-egress",
			Description: "Intercept package manager commands without explicit registry pin (multiline-hardened)",
			Expression:  `tool == "run_command" && has(args.command) && args.command.matches("(?s).*(npm|pip|cargo)\\s+(install|add).*") && !args.command.contains("--registry")`,
			Action:      DecisionInterceptApproval,
			Severity:    "MEDIUM",
		},
	}

	for _, r := range defaults {
		if err := e.AddRule(r); err != nil {
			return fmt.Errorf("failed to compile default rule %s: %w", r.ID, err)
		}
	}
	return nil
}

// AddRule compiles and appends a CEL policy rule.
func (e *CELPolicyEngine) AddRule(rule *Rule) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	ast, issues := e.env.Compile(rule.Expression)
	if issues != nil && issues.Err() != nil {
		return fmt.Errorf("syntax error in CEL expression %q: %w", rule.Expression, issues.Err())
	}

	prg, err := e.env.Program(ast)
	if err != nil {
		return fmt.Errorf("failed to instantiate CEL program for rule %s: %w", rule.ID, err)
	}

	rule.program = prg
	e.rules = append(e.rules, rule)
	return nil
}

// EvaluateToolCall tests a tool call against all compiled rules in order of precedence.
// Any CEL runtime evaluation error (e.g. unexpected argument type overload failure) fails closed with DecisionDeny.
func (e *CELPolicyEngine) EvaluateToolCall(ctx context.Context, toolName string, args map[string]any, workspace, profile string) (Decision, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if args == nil {
		args = make(map[string]any)
	}

	activation := map[string]any{
		"tool":      toolName,
		"args":      args,
		"workspace": workspace,
		"profile":   profile,
	}

	for _, rule := range e.rules {
		select {
		case <-ctx.Done():
			return DecisionDeny, ctx.Err()
		default:
		}

		out, _, err := rule.program.Eval(activation)
		if err != nil {
			// Fail closed on CEL evaluation errors so type confusion or runtime errors never bypass policy.
			return DecisionDeny, fmt.Errorf("CEL rule %s evaluation failed (fail-closed): %w", rule.ID, err)
		}

		if match, ok := out.Value().(bool); ok && match {
			return rule.Action, nil
		}
	}

	return DecisionAllow, nil
}
