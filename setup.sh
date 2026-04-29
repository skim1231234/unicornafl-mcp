#!/usr/bin/env bash
# unicornafl-mcp setup script
# Target: arm64 macOS (Apple Silicon), Python 3.11+
#
# What this does:
#   1. Verifies the environment (macOS, Python, Homebrew, git)
#   2. Installs AFL++ via Homebrew if missing
#   3. Installs / updates the Rust toolchain (rustc >= 1.87 required)
#   4. Fetches the unicornafl source into ./vendor/unicornafl/
#      (or wherever UNICORNAFL_SRC points)
#   5. Builds the unicornafl wheel and installs it into ./.venv/
#      together with unicorn / capstone / mcp
#   6. Registers the server in Claude Desktop's config (with backup),
#      preserving any other mcpServers entries you already have.
#
# Re-running is safe — every step is idempotent.
#
# Flags:
#   --no-register    Do not modify Claude Desktop's config (build only).
#   --yes / -y       Non-interactive: assume "yes" on every prompt.
#
# Environment overrides:
#   UNICORNAFL_SRC=/path/to/checkout    Use an existing unicornafl checkout
#                                        instead of cloning into ./vendor/.
#   UNICORNAFL_REF=main                  git ref (branch/tag/commit) to clone
#                                        when fetching upstream. Default: main.
#   PYTHON_BIN=python3.11                Python interpreter to use.
#   VENV_DIR=./custom-venv               Override venv location.
#   CLAUDE_CONFIG=/path/to/config.json   Override Claude Desktop config path
#                                        (auto-detected per OS by default).

set -euo pipefail

# ---------- Flag parsing ----------
REGISTER=1
ASSUME_YES=0
for arg in "$@"; do
    case "$arg" in
        --no-register) REGISTER=0 ;;
        --yes|-y)      ASSUME_YES=1 ;;
        -h|--help)
            awk 'NR==1{next} /^[^#]/{exit} {sub(/^# ?/,""); print}' "$0"
            exit 0 ;;
        *)
            printf '\033[1;31m[fail ]\033[0m unknown flag: %s\n' "$arg" >&2
            exit 2 ;;
    esac
done

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_VENDOR_DIR="${PROJECT_ROOT}/vendor/unicornafl"
LEGACY_VENDOR_DIR="${PROJECT_ROOT}/unicornafl-main"   # pre-0.2 default

# Resolve the unicornafl source location:
#   1. UNICORNAFL_SRC env var → use as-is (must exist)
#   2. ./vendor/unicornafl/ if present
#   3. ./unicornafl-main/   if present (legacy, kept for backward compat)
#   4. Otherwise: clone upstream into ./vendor/unicornafl/
if [ -n "${UNICORNAFL_SRC:-}" ]; then
    UNICORNAFL_SRC="$UNICORNAFL_SRC"
elif [ -d "$DEFAULT_VENDOR_DIR" ]; then
    UNICORNAFL_SRC="$DEFAULT_VENDOR_DIR"
elif [ -d "$LEGACY_VENDOR_DIR" ]; then
    UNICORNAFL_SRC="$LEGACY_VENDOR_DIR"
else
    UNICORNAFL_SRC="$DEFAULT_VENDOR_DIR"
fi
UNICORNAFL_REF="${UNICORNAFL_REF:-main}"
VENV_DIR="${VENV_DIR:-${PROJECT_ROOT}/.venv}"
PYTHON_BIN="${PYTHON_BIN:-python3.11}"

log()  { printf '\033[1;34m[setup]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn ]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[fail ]\033[0m %s\n' "$*" >&2; exit 1; }

# ---------- 1. Sanity checks ----------
log "Checking environment..."
[ "$(uname -s)" = "Darwin" ] || fail "This script targets macOS only."
[ "$(uname -m)" = "arm64" ]  || warn "Not arm64 — script will continue but was designed for Apple Silicon."

if ! command -v "$PYTHON_BIN" >/dev/null; then
    fail "$PYTHON_BIN not found. Install Python 3.11 (brew install python@3.11) or set PYTHON_BIN."
fi
PY_VER=$("$PYTHON_BIN" -c 'import sys; print("{}.{}".format(*sys.version_info[:2]))')
log "Python: $PYTHON_BIN ($PY_VER)"

if ! command -v brew >/dev/null; then
    fail "Homebrew not found. Install from https://brew.sh first."
fi
if ! command -v git >/dev/null; then
    fail "git not found. Install Xcode Command Line Tools (xcode-select --install)."
fi

# ---------- 2. unicornafl source ----------
if [ ! -d "$UNICORNAFL_SRC" ]; then
    log "Fetching unicornafl into $UNICORNAFL_SRC (ref=$UNICORNAFL_REF)..."
    mkdir -p "$(dirname "$UNICORNAFL_SRC")"
    git clone --depth 1 --branch "$UNICORNAFL_REF" \
        https://github.com/AFLplusplus/unicornafl "$UNICORNAFL_SRC" \
        || fail "git clone https://github.com/AFLplusplus/unicornafl failed."
else
    log "Using existing unicornafl source at $UNICORNAFL_SRC"
fi
[ -f "$UNICORNAFL_SRC/Cargo.toml" ] || \
    fail "$UNICORNAFL_SRC does not look like a unicornafl checkout (no Cargo.toml)."

# ---------- 3. AFL++ ----------
if command -v afl-fuzz >/dev/null; then
    log "AFL++ already installed: $(afl-fuzz -h 2>&1 | head -1 || true)"
else
    log "Installing AFL++ via Homebrew..."
    brew install afl++ || fail "brew install afl++ failed."
fi

# ---------- 4. Rust toolchain + maturin ----------
if ! command -v cargo >/dev/null; then
    log "Installing Rust (rustup)..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
    # shellcheck disable=SC1091
    source "$HOME/.cargo/env"
else
    log "Rust already installed: $(rustc --version)"
fi

# Ensure rustc >= 1.87 (unicornafl requirement)
RUST_MAJOR=$(rustc --version | awk '{print $2}' | cut -d. -f1)
RUST_MINOR=$(rustc --version | awk '{print $2}' | cut -d. -f2)
if (( RUST_MAJOR < 1 || (RUST_MAJOR == 1 && RUST_MINOR < 87) )); then
    log "Updating Rust (>=1.87 required)..."
    rustup update stable
fi

# ---------- 5. Python venv + MCP deps ----------
if [ ! -d "$VENV_DIR" ]; then
    log "Creating venv at $VENV_DIR"
    "$PYTHON_BIN" -m venv "$VENV_DIR"
fi
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

log "Upgrading pip / installing build & MCP deps..."
pip install --upgrade pip wheel >/dev/null
pip install --upgrade \
    "maturin>=1.8,<2.0" \
    "unicorn>=2.1.3" \
    "capstone" \
    "mcp>=1.2.0" \
    "pydantic>=2"

# ---------- 6. Build & install unicornafl ----------
if python -c "import unicornafl" 2>/dev/null; then
    log "unicornafl already importable: $(python -c 'import unicornafl, os; print(os.path.dirname(unicornafl.__file__))')"
else
    log "Building unicornafl from source ($UNICORNAFL_SRC)..."
    pushd "$UNICORNAFL_SRC" >/dev/null
    cargo build --release
    maturin build --release --interpreter "$(command -v python)"
    WHEEL=$(ls -t target/wheels/unicornafl-*.whl | head -1 || true)
    [ -n "$WHEEL" ] || fail "Could not find produced wheel under target/wheels."
    log "Installing wheel: $WHEEL"
    pip install --force-reinstall "$WHEEL"
    popd >/dev/null
fi

# ---------- 7. Smoke test ----------
log "Smoke test: importing unicorn + unicornafl..."
python - <<'PY'
import unicorn, unicornafl
print(f"  unicorn    {unicorn.__version__}")
print(f"  unicornafl OK -> {unicornafl.__file__}")
PY

# ---------- 8. Render a Claude Desktop config snippet ----------
GENERATED_CONFIG="${PROJECT_ROOT}/claude_desktop_config.local.json"
cat > "$GENERATED_CONFIG" <<EOF
{
  "mcpServers": {
    "unicornafl": {
      "command": "${VENV_DIR}/bin/python",
      "args": ["${PROJECT_ROOT}/server.py"],
      "env": { "PYTHONUNBUFFERED": "1" }
    }
  }
}
EOF

# ---------- 9. Auto-register with Claude Desktop ----------
# Allow user override; otherwise auto-detect per OS.
if [ -z "${CLAUDE_CONFIG:-}" ]; then
    case "$(uname -s)" in
        Darwin) CLAUDE_CONFIG="$HOME/Library/Application Support/Claude/claude_desktop_config.json" ;;
        Linux)  CLAUDE_CONFIG="$HOME/.config/Claude/claude_desktop_config.json" ;;
        *)      CLAUDE_CONFIG="" ;;
    esac
fi

if [ "$REGISTER" -eq 0 ]; then
    log "Skipping Claude Desktop registration (--no-register)."
elif [ -z "$CLAUDE_CONFIG" ]; then
    warn "Unsupported OS for auto-registration."
    warn "Set CLAUDE_CONFIG=/path/to/claude_desktop_config.json and re-run, or"
    warn "merge $GENERATED_CONFIG into your config manually."
else
    log "Will register at: $CLAUDE_CONFIG"
    if [ ! -e "$CLAUDE_CONFIG" ]; then
        warn "Config file does not exist yet — will be created."
        warn "If your Claude Desktop uses a different path, abort and re-run with"
        warn "   CLAUDE_CONFIG=/your/actual/path/claude_desktop_config.json ./setup.sh"
    fi
    if [ "$ASSUME_YES" -eq 1 ]; then
        proceed=1
    else
        printf '\033[1;34m[setup]\033[0m Proceed with registration at the path above? [Y/n] '
        read -r ans || ans=""
        case "$(printf '%s' "$ans" | tr '[:upper:]' '[:lower:]')" in
            n|no) proceed=0 ;;
            *)    proceed=1 ;;
        esac
    fi

    if [ "$proceed" -eq 1 ]; then
        mkdir -p "$(dirname "$CLAUDE_CONFIG")"
        python - "$CLAUDE_CONFIG" "$VENV_DIR/bin/python" "$PROJECT_ROOT/server.py" <<'PY'
import json, os, shutil, sys, time

config_path, py_bin, server_py = sys.argv[1], sys.argv[2], sys.argv[3]
existed = os.path.exists(config_path)
cfg = {}
if existed:
    try:
        with open(config_path) as f:
            cfg = json.load(f)
    except json.JSONDecodeError as e:
        print(f"[setup] Existing config is not valid JSON ({e}); aborting merge.")
        sys.exit(1)
    bak = f"{config_path}.bak.{int(time.time())}"
    shutil.copy(config_path, bak)
    print(f"[setup] Backed up existing config → {bak}")

cfg.setdefault("mcpServers", {})
cfg["mcpServers"]["unicornafl"] = {
    "command": py_bin,
    "args": [server_py],
    "env": {"PYTHONUNBUFFERED": "1"},
}
with open(config_path, "w") as f:
    json.dump(cfg, f, indent=2)
print(f"[setup] {'Updated' if existed else 'Created'} {config_path}")
print(f"[setup] mcpServers entries now: {sorted(cfg['mcpServers'].keys())}")
PY
        REGISTERED=1
    else
        log "Registration declined. The merged config is at $GENERATED_CONFIG."
        REGISTERED=0
    fi
fi

cat <<EOF

=========================================================================
 Setup complete.

   unicornafl source : $UNICORNAFL_SRC
   Python venv       : $VENV_DIR
   MCP entry point   : $PROJECT_ROOT/server.py
EOF

if [ "${REGISTERED:-0}" -eq 1 ]; then
cat <<EOF

 Claude Desktop config updated:
   $CLAUDE_CONFIG

 NEXT STEP:  fully quit and relaunch Claude Desktop, then check the tools
 panel — all 48 unicornafl-mcp tools should appear.
=========================================================================
EOF
else
cat <<EOF

 Manual registration required. A ready-to-paste config snippet is at:
   $GENERATED_CONFIG

 Merge its contents into Claude Desktop's config:
   $CLAUDE_CONFIG

 Then fully quit and relaunch Claude Desktop.
=========================================================================
EOF
fi
