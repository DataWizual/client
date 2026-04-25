#!/bin/bash
# ============================================================
#  Auditor Core v2.2 — Smart Installer & Launcher
#  Supports: first-run setup + repeated runs (idempotent)
#  Modes: source (.py) and compiled (.so)
# ============================================================
set -euo pipefail

GREEN='\033[0;32m'; BLUE='\033[0;34m'; YELLOW='\033[1;33m'
RED='\033[0;31m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()      { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }
section() { echo -e "\n${BOLD}${CYAN}══ $* ══${NC}"; }

# ── Detect runtime mode ──────────────────────────────────────
SO_COUNT=$(find auditor/ -name "*.so" 2>/dev/null | wc -l | tr -d ' ')
if [ "$SO_COUNT" -gt "3" ]; then
    RUNTIME_MODE="compiled"
else
    RUNTIME_MODE="source"
fi

# ── Banner ───────────────────────────────────────────────────
echo -e "${BLUE}"
echo "  ╔═══════════════════════════════════════════════╗"
echo "  ║          Auditor Core v2.2                    ║"
echo "  ║   Deterministic Security Intelligence Layer   ║"
echo "  ╚═══════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "  Mode: ${CYAN}${RUNTIME_MODE}${NC} | Platform: $(uname -s) $(uname -m) | Python: $(python3 --version 2>&1 | cut -d' ' -f2)"
echo ""

# ── 1. Terms of Use ──────────────────────────────────────────
echo "------------------------------------------------------------"
echo "  DATAWIZUAL SECURITY GATE: INSTALLATION"
echo "------------------------------------------------------------"
echo "  IMPORTANT: This installation is subject to the Terms of Use"
echo "  defined in the TERMS_OF_USE.md file."
echo ""
echo "  By typing YES, you acknowledge that:"
echo "  1. Software is provided 'AS-IS' (No Financial Liability)."
echo "  2. You are responsible for all security decisions & overrides."
echo "  3. Machine ID submission constitutes full acceptance of Terms."
echo "------------------------------------------------------------"
echo ""
read -r -p "  Type YES to accept terms and proceed: " confirm
if [ "$confirm" != "YES" ]; then
    echo -e "${RED}❌ Installation aborted. Terms of Use must be accepted.${NC}"
    exit 1
fi
ok "Terms accepted."

# ── 2. Environment Configuration ────────────────────────────
section "Environment Configuration"

if [ -f .env ]; then
    info "Existing .env found — skipping configuration."
    info "Delete .env to reconfigure from scratch."
else
    if [ ! -f .env.example ]; then
        error ".env.example not found. Cannot configure environment."
    fi

    info "Configuring environment..."
    cp .env.example .env

    # ── Machine ID (для лицензии) ────────────────────────────
    echo ""
    info "Retrieving your Machine ID for license binding..."
    MACHINE_ID=$(python3 -c "
import sys
sys.path.insert(0, '.')
try:
    from auditor.security.guard import AuditorGuard
    print(AuditorGuard().get_machine_id())
except Exception as e:
    print(f'UNAVAILABLE ({e})')
" 2>/dev/null || echo "UNAVAILABLE")

    echo ""
    echo -e "  ┌─────────────────────────────────────────┐"
    echo -e "  │  Machine ID: ${CYAN}${BOLD}${MACHINE_ID}${NC}"
    echo -e "  │  Send to: eldorzufarov66@gmail.com"
    echo -e "  │  You will receive your License Key."
    echo -e "  └─────────────────────────────────────────┘"
    echo ""

    # ── Collect credentials ──────────────────────────────────
    read -r -p "  Enter AUDITOR_LICENSE_KEY: " license_key
    read -r -s -p "  Enter DB_PASSWORD: " db_password
    echo ""
    read -r -s -p "  Enter Google Gemini API Key: " gemini_key
    echo ""
    read -r -s -p "  Enter Groq API Key (fallback AI, press Enter to skip): " groq_key
    echo ""

    # ── Fill placeholders via python3 ────────────────────────
    python3 - "$license_key" "$db_password" "$gemini_key" "$groq_key" << 'PYEOF'
import sys

license_key, db_password, gemini_key, groq_key = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

with open('.env') as f:
    content = f.read()

replacements = {
    'YOUR_LICENSE_KEY_HERE':    license_key,
    'SET_STRONG_PASSWORD_HERE': db_password,
    'YOUR_GOOGLE_API_KEY_HERE': gemini_key,
}

if groq_key:
    replacements['YOUR_GROQ_API_KEY_HERE'] = groq_key

for placeholder, value in replacements.items():
    content = content.replace(placeholder, value)

with open('.env', 'w') as f:
    f.write(content)
PYEOF

    # ── Validate no placeholders remain ──────────────────────
    if grep -qE "YOUR_LICENSE_KEY_HERE|SET_STRONG_PASSWORD_HERE|YOUR_GOOGLE_API_KEY_HERE" .env; then
        rm -f .env
        error ".env still contains unfilled placeholders. Check .env.example."
    fi

    chmod 600 .env
    ok ".env configured (mode 600)."
fi

# ── 3. Infrastructure (Docker + PostgreSQL) ──────────────────
section "Infrastructure"

if ! docker info > /dev/null 2>&1; then
    error "Docker is not running. Please start Docker first."
fi

info "Starting services via docker-compose..."
docker-compose up -d --wait 2>&1 | tail -5
ok "Docker services are up."

# ── 4. Python Virtual Environment ───────────────────────────
section "Python Environment"

if [ -d "venv" ]; then
    info "Existing virtual environment found."
else
    info "Creating Python virtual environment..."
    python3 -m venv venv
fi

# shellcheck source=/dev/null
source venv/bin/activate
ok "Virtual environment activated."

# ── 5. Dependencies ──────────────────────────────────────────
section "Dependencies"

info "Syncing dependencies..."
pip install -q --upgrade pip

if [ -f "requirements.txt" ]; then
    pip install -q -r requirements.txt
    ok "Dependencies installed."
else
    warn "requirements.txt not found — skipping pip install."
fi

# ── 6. Cython compilation (source mode only) ─────────────────
if [ "$RUNTIME_MODE" = "source" ] && [ -f "build_cython.py" ]; then
    section "Optional: Cython Compilation"
    echo ""
    read -r -p "  Compile modules to .so for IP protection? [y/N]: " DO_COMPILE
    DO_COMPILE="${DO_COMPILE:-N}"

    if [[ "$DO_COMPILE" =~ ^[Yy] ]]; then
        info "Installing Cython..."
        pip install -q cython

        info "Compiling modules (this may take 2–5 minutes)..."
        python3 build_cython.py build_ext --inplace 2>&1 | \
            grep -E "(Compiling|error:|✅|❌)" || true

        SO_AFTER=$(find auditor/ -name "*.so" 2>/dev/null | wc -l | tr -d ' ')
        ok "Compiled ${SO_AFTER} modules to .so"
        RUNTIME_MODE="compiled"
    else
        info "Skipping compilation — running in source mode."
    fi
fi

# ── 7. Finalize ──────────────────────────────────────────────
section "Finalizing"

chmod +x audit
ok "'./audit' is executable."

echo ""
echo -e "${GREEN}${BOLD}══════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  ✅ READY TO GO!${NC}"
echo -e "${GREEN}${BOLD}══════════════════════════════════════════${NC}"
echo ""
echo -e "  Mode:  ${CYAN}${RUNTIME_MODE}${NC}"
echo -e "  Usage: ${YELLOW}./audit <target_path_or_link>${NC}"
echo "--------------------------------------------------"

if ./audit --version 2>/dev/null; then
    ok "Verification passed."
else
    warn "Version check failed — setup complete but check dependencies."
fi