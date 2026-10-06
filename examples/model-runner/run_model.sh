#!/usr/bin/env bash
# ==============================================================================
# run_model.sh - Secure AI Model Runner with Aegisbox & Locksmith
#
# Retrieves an API key from Locksmith (biometric credential manager) and launches
# an AI model via agi inside an isolated Aegisbox sandbox container.
# ==============================================================================

set -euo pipefail

# Default configuration
LOCKSMITH_KEY="${LOCKSMITH_KEY:-GEMINI_API_KEY}"
ENV_VAR_NAME="${ENV_VAR_NAME:-GEMINI_API_KEY}"
MODEL="${MODEL:-gemini-3.8-flash-medium}"
SANDBOX_ENGINE="${SANDBOX_ENGINE:-local}"
PROMPT=""
INTERACTIVE=0
INJECT_FILES=()
EXTRA_ARGS=()

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS] [-- ADDITIONAL_ARGS...]

Securely runs an AI model in an Aegisbox sandbox using an API key retrieved from Locksmith.

Options:
  -k, --key <name>        Locksmith secret key to retrieve (default: GEMINI_API_KEY)
  -e, --env-var <name>    Environment variable name to forward (default: GEMINI_API_KEY)
  -m, --model <model>     Model identifier (default: gemini-3.8-flash-medium)
  -p, --prompt <text>     Prompt to run non-interactively
  -i, --interactive       Launch agi in interactive mode
  -j, --inject <path>     Inject file into sandbox (e.g. CLAUDE.md=~/.claude/CLAUDE.md or prompt.txt)
      --engine <engine>   Aegisbox engine: 'local' or 'microvm' (default: local)
  -h, --help              Show this help message and exit

Examples:
  # Run a prompt using the default Gemini key from Locksmith
  ./run_model.sh -p "Explain how quantum computing works in 3 bullets"

  # Run with a custom model and Locksmith key
  ./run_model.sh -k ANTHROPIC_API_KEY -e ANTHROPIC_API_KEY -m claude-sonnet-4-6 -p "Hello Claude!"

  # Launch an interactive agent session inside the sandbox
  ./run_model.sh -i

  # Launch an interactive session with injected CLAUDE.md instructions
  ./run_model.sh -i -j CLAUDE.md=~/.claude/CLAUDE.md

  # Pass custom flags directly to agi
  ./run_model.sh -- --effort high -p "Analyze project architecture"
EOF
    exit 0
}

# Parse command line options
while [[ $# -gt 0 ]]; do
    case "$1" in
        -k|--key)
            LOCKSMITH_KEY="$2"
            shift 2
            ;;
        -e|--env-var)
            ENV_VAR_NAME="$2"
            shift 2
            ;;
        -m|--model)
            MODEL="$2"
            shift 2
            ;;
        -p|--prompt)
            PROMPT="$2"
            shift 2
            ;;
        -i|--interactive)
            INTERACTIVE=1
            shift
            ;;
        -j|--inject)
            INJECT_FILES+=("$2")
            shift 2
            ;;
        --engine)
            SANDBOX_ENGINE="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        --)
            shift
            EXTRA_ARGS=("$@")
            break
            ;;
        *)
            # Collect unparsed arguments
            EXTRA_ARGS+=("$1")
            shift
            ;;
    esac
done

# Step 1: Verify prerequisites
check_dependency() {
    local cmd="$1"
    if ! command -v "$cmd" &>/dev/null; then
        echo "❌ Error: Required tool '$cmd' is not installed or not in PATH." >&2
        return 1
    fi
}

check_dependency "locksmith" || exit 1
check_dependency "aegisbox" || exit 1

# Find the agi or agy binary
AGI_BIN="agi"
if ! command -v "$AGI_BIN" &>/dev/null; then
    if command -v "agy" &>/dev/null; then
        AGI_BIN="agy"
    else
        echo "❌ Error: Neither 'agi' nor 'agy' command was found." >&2
        exit 1
    fi
fi

# Step 2: Retrieve API Key from Locksmith
echo "🔑 Retrieving '$LOCKSMITH_KEY' from Locksmith..."

# Ensure we cleanup sensitive variable when this script terminates
cleanup() {
    unset API_KEY_SECRET "$ENV_VAR_NAME" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Query Locksmith
if ! API_KEY_SECRET="$(locksmith get "$LOCKSMITH_KEY" 2>&1)"; then
    echo "❌ Error: Failed to retrieve API key '$LOCKSMITH_KEY' from Locksmith." >&2
    echo "Details: $API_KEY_SECRET" >&2
    echo "" >&2
    echo "Tip: Store the key in Locksmith first using:" >&2
    echo "  locksmith add $LOCKSMITH_KEY" >&2
    exit 1
fi

if [[ -z "${API_KEY_SECRET:-}" ]]; then
    echo "❌ Error: Secret '$LOCKSMITH_KEY' in Locksmith is empty." >&2
    exit 1
fi

echo "✅ Secret '$LOCKSMITH_KEY' successfully retrieved from Locksmith."

# Step 3: Prepare environment and execution command
export "$ENV_VAR_NAME"="$API_KEY_SECRET"

# Build inner agi command line
CMD_TO_RUN=("$AGI_BIN" "--model" "$MODEL")

if [[ $INTERACTIVE -eq 1 ]]; then
    if [[ -n "$PROMPT" ]]; then
        CMD_TO_RUN+=("-i" "$PROMPT")
    fi
elif [[ -n "$PROMPT" ]]; then
    CMD_TO_RUN+=("-p" "$PROMPT")
fi

if [[ ${#EXTRA_ARGS[@]} -gt 0 ]]; then
    CMD_TO_RUN+=("${EXTRA_ARGS[@]}")
fi

# Quote arguments safely for execution inside aegisbox
ESCAPED_CMD=""
for arg in "${CMD_TO_RUN[@]}"; do
    ESCAPED_CMD+="$(printf '%q ' "$arg")"
done

# Step 4: Execute inside Aegisbox sandbox
AEGISBOX_FLAGS=()
if [[ $INTERACTIVE -eq 1 ]]; then
    AEGISBOX_FLAGS+=("-i")
    if [[ "$SANDBOX_ENGINE" == "microvm" ]]; then
        echo "⚠️  Interactive terminal sessions require direct TTY; switching engine to local." >&2
        SANDBOX_ENGINE="local"
    fi
fi

for inj in "${INJECT_FILES[@]}"; do
    AEGISBOX_FLAGS+=("--inject" "$inj")
done

exec aegisbox exec \
    "${AEGISBOX_FLAGS[@]}" \
    --engine="$SANDBOX_ENGINE" \
    --allow-env="$ENV_VAR_NAME,HOME" \
    "$ESCAPED_CMD"

