#!/bin/bash
# =================================================================
# SENTINEL CORE DEMO — PROVISIONING SCRIPT
# DataWizual Security (c) 2026
# =================================================================

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

ok()   { echo -e "${GREEN}✅ $1${NC}"; }
info() { echo -e "${BLUE}ℹ️  $1${NC}"; }
warn() { echo -e "${YELLOW}⚠️  $1${NC}"; }
fail() { echo -e "${RED}❌ $1${NC}"; exit 1; }

# =================================================================
# STEP 1 — TERMS OF USE
# =================================================================
echo ""
echo -e "${BOLD}------------------------------------------------------------"
echo "🛡️  DATAWIZUAL SECURITY — SENTINEL CORE DEMO"
echo "------------------------------------------------------------${NC}"
echo "This installation is subject to the Terms of Use"
echo "defined in TERMS_OF_USE.md."
echo ""
echo "By typing YES, you acknowledge that:"
echo "  1. Software is provided 'AS-IS' (No Financial Liability)."
echo "  2. You are responsible for all security decisions & overrides."
echo "  3. Machine ID submission constitutes full acceptance of Terms."
echo "------------------------------------------------------------"
echo ""
read -p "Type YES to accept terms and proceed: " confirm
[ "$confirm" != "YES" ] && fail "Installation aborted. Terms of Use must be accepted."

# =================================================================
# STEP 2 — PYTHON CHECK
# =================================================================
info "Checking Python version..."
python3 --version >/dev/null 2>&1 || fail "Python 3 not found. Install Python 3.10+ and retry."
PY_VER=$(python3 -c "import sys; print(sys.version_info.minor)")
[ "$PY_VER" -lt 10 ] && fail "Python 3.10+ required. Found: $(python3 --version)"
ok "Python OK"

# =================================================================
# STEP 3 — VIRTUAL ENVIRONMENT
# =================================================================
if [ ! -d "venv" ]; then
    info "Creating virtual environment..."
    python3 -m venv venv
fi
source venv/bin/activate
SENTINEL_BIN="$(pwd)/venv/bin/sentinel"
info "Installing dependencies..."
pip install -q --upgrade pip
ok "pip updated"

# =================================================================
# STEP 4 — INSTALL SENTINEL FROM LOCAL SOURCE
# =================================================================
info "Installing Sentinel Core..."
pip install -q -e . && ok "Sentinel Core installed"

# =================================================================
# STEP 5 — MACHINE ID
# =================================================================
echo ""
info "Detecting Machine ID..."
MACHINE_ID=$(python3 -c "
try:
    from auditor.security.guard import AuditorGuard
    print(AuditorGuard().get_machine_id())
except Exception:
    print('UNKNOWN')
" 2>/dev/null || echo "UNKNOWN")

echo ""
echo -e "${BOLD}  Your Machine ID: ${YELLOW}${MACHINE_ID}${NC}"
echo ""

# =================================================================
# STEP 6 — LICENSE KEY (optional for trial)
# =================================================================
echo -e "${YELLOW}📋 License Key Setup${NC}"
echo "You have 3 free trial runs without a license key."
echo "To get a full license: eldorzufarov66@gmail.com"
echo ""
read -p "  Enter License Key (press Enter to use trial mode): " license_key

# =================================================================
# STEP 7 — ENVIRONMENT CONFIGURATION
# =================================================================
if [ ! -f ".env" ]; then
    cp .env.example .env

    read -s -p "  Enter GitHub Alert Token (press Enter to skip): " alert_token
    echo ""
    read -p "  Enter Admin Repo [your-org/your-repo]: " admin_repo
    admin_repo=${admin_repo:-your-org/your-repo}
    read -s -p "  Enter Google Gemini API Key (press Enter to skip): " gemini_key
    echo ""

    python3 - << PYEOF
content = open('.env').read()
replacements = {
    'YOUR_LICENSE_KEY_HERE': '${license_key}',
    'YOUR_GITHUB_TOKEN_HERE': '${alert_token}',
    'DataWizual/sentinel-core': '${admin_repo}',
    'YOUR_GEMINI_API_KEY_HERE': '${gemini_key}',
}
for old, new in replacements.items():
    content = content.replace(old, new)
open('.env', 'w').write(content)
PYEOF

    chmod 600 .env
    ok ".env configured"
fi

# =================================================================
# STEP 8 — SENTINEL INIT (skip if trial mode)
# =================================================================
if [ -n "$license_key" ]; then
    info "Initializing Sentinel with license..."
    source .env 2>/dev/null || true
    SENTINEL_LICENSE_KEY="$license_key" \
    AUDITOR_LICENSE_KEY="$license_key" \
    "$SENTINEL_BIN" init \
        --token "${alert_token:-$SENTINEL_ALERT_TOKEN}" \
        --repo "${admin_repo:-$SENTINEL_ADMIN_REPO}" \
        && ok "Sentinel initialized" \
        || warn "Init failed — running in trial mode"
else
    echo -e "${YELLOW}⚠️  No license key — trial mode active (3 free runs).${NC}"
fi

# =================================================================
# STEP 9 — PRE-COMMIT HOOK
# =================================================================
if [ ! -d ".git" ]; then
    info "No git repository found — skipping pre-commit hook"
    info "To install hook later: run start.sh inside a git repository"
else
    info "Installing pre-commit security hook..."
    rm -f .git/hooks/pre-commit

    cat > .git/hooks/pre-commit << HOOKEOF
#!/bin/bash
SENTINEL="${SENTINEL_BIN}"
echo "🔍 Sentinel is verifying commit security..."
"\${SENTINEL}" scan . || exit 1
HOOKEOF

    chmod +x .git/hooks/pre-commit
    ok "Pre-commit hook installed"
fi

# =================================================================
# DONE
# =================================================================
unset gemini_key alert_token license_key
history -c 2>/dev/null || true

echo ""
echo -e "${BOLD}${GREEN}------------------------------------------------------------"
echo "✅ SENTINEL CORE DEMO READY"
echo "------------------------------------------------------------${NC}"
echo ""
echo -e "  Run security scan:  ${YELLOW}${SENTINEL_BIN} scan .${NC}"
echo -e "  Run with report:    ${YELLOW}${SENTINEL_BIN} scan . --report${NC}"
echo -e "  View Machine ID:    ${YELLOW}${SENTINEL_BIN} --id${NC}"
echo ""
echo -e "${YELLOW}💡 To activate venv in a new terminal: source venv/bin/activate${NC}"
echo ""

# Keep venv active in current shell
exec bash --rcfile <(echo "source $(pwd)/venv/bin/activate; echo -e '${GREEN}✅ Sentinel Core venv active${NC}'")
