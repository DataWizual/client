#!/bin/bash
# =================================================================
# SENTINEL CORE — UNIFIED PROVISIONING SCRIPT
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
echo "🛡️  DATAWIZUAL SECURITY — SENTINEL CORE INSTALLATION"
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
info "Installing/updating dependencies..."
pip install -q --upgrade pip
ok "pip updated"

# =================================================================
# STEP 4 — INSTALL SENTINEL FROM GITHUB (до Machine ID — нужен sentinel)
# =================================================================
echo ""
info "Installing Sentinel Core from GitHub..."

read -p "  Enter Install Token (PAT with repo scope): " install_token
if [ -n "$install_token" ]; then
    REPO="DataWizual/sentinel-core-v2_1"
    pip install -q \
        git+https://x-access-token:${install_token}@github.com/${REPO}.git@main \
        && ok "Sentinel installed from GitHub" \
        || warn "GitHub install failed — using local version"
    unset install_token
else
    info "No install token — installing from local source..."
    pip install -q -e . && ok "Installed from local source"
fi

# =================================================================
# STEP 5 — COPY CONFIG FILES FROM INSTALLED PACKAGE
# =================================================================
info "Copying configuration files from package..."

PKG_DIR=$(python3 -c "
import importlib.util, os
spec = importlib.util.find_spec('sentinel')
if spec:
    print(os.path.dirname(os.path.dirname(spec.origin)))
" 2>/dev/null || echo "")

if [ -n "$PKG_DIR" ] && [ -d "$PKG_DIR" ]; then
    ok "Package found at: $PKG_DIR"
    [ ! -f "audit-config.yml" ]        && [ -f "$PKG_DIR/audit-config.yml" ]        && cp "$PKG_DIR/audit-config.yml" .        && ok "audit-config.yml copied"
    [ ! -f ".pre-commit-config.yaml" ] && [ -f "$PKG_DIR/.pre-commit-config.yaml" ] && cp "$PKG_DIR/.pre-commit-config.yaml" . && ok ".pre-commit-config.yaml copied"
    [ ! -f "sentinel.yaml" ]           && [ -f "$PKG_DIR/sentinel.yaml" ]           && cp "$PKG_DIR/sentinel.yaml" .           && ok "sentinel.yaml copied"
    [ ! -f ".env.example" ]            && [ -f "$PKG_DIR/.env.example" ]            && cp "$PKG_DIR/.env.example" .            && ok ".env.example copied"
    [ ! -f "TERMS_OF_USE.md" ]         && [ -f "$PKG_DIR/TERMS_OF_USE.md" ]         && cp "$PKG_DIR/TERMS_OF_USE.md" .         && ok "TERMS_OF_USE.md copied"
else
    warn "Could not locate package directory — config files may need to be copied manually"
fi

# =================================================================
# STEP 6 — MACHINE ID (теперь sentinel уже установлен)
# =================================================================
echo ""
info "Detecting Machine ID for license binding..."
MACHINE_ID=$(python3 -c "
import os
os.environ.setdefault('AUDITOR_LICENSE_SALT', 'placeholder')
try:
    from auditor.security.guard import AuditorGuard
    print(AuditorGuard().get_machine_id())
except Exception:
    print('UNKNOWN')
" 2>/dev/null || echo "UNKNOWN")
echo ""
echo -e "${BOLD}  Your Machine ID: ${YELLOW}${MACHINE_ID}${NC}"
echo ""
echo "  Send this ID to DataWizual Security to receive your License Key."
echo "  Contact: eldorzufarov66@gmail.com"
echo ""

# =================================================================
# STEP 7 — ENVIRONMENT CONFIGURATION (.env)
# =================================================================
if [ ! -f ".env" ]; then
    info "Configuring environment..."
    [ ! -f ".env.example" ] && fail ".env.example not found."
    cp .env.example .env

    echo ""
    read -p "  Enter License Key: " license_key
    [ -z "$license_key" ] && fail "License Key is required."

    read -s -p "  Enter Google Gemini API Key: " gemini_key
    echo ""
    [ -z "$gemini_key" ] && warn "Gemini API Key not set. AI analysis will be disabled."

    read -p "  Enter Gemini Model [gemini-2.5-flash]: " gemini_model
    gemini_model=${gemini_model:-gemini-2.5-flash}

    read -s -p "  Enter GitHub Alert Token: " alert_token
    echo ""
    [ -z "$alert_token" ] && warn "GitHub Alert Token not set. Remote reporting disabled."

    read -p "  Enter Admin Repo [DataWizual/sentinel-core-v2_1]: " admin_repo
    admin_repo=${admin_repo:-DataWizual/sentinel-core-v2_1}

    read -s -p "  Enter License Salt (AUDITOR_LICENSE_SALT): " license_salt
    echo ""

    python3 - << PYEOF
content = open('.env').read()
replacements = {
    'YOUR_LICENSE_KEY_HERE': '${license_key}',
    'YOUR_GEMINI_API_KEY_HERE': '${gemini_key}',
    '<KEY>': '${gemini_key}',
    'gemini-2.5-flash': '${gemini_model}',
    'YOUR_GITHUB_TOKEN_HERE': '${alert_token}',
    'YourOrg/sentinel-core': '${admin_repo}',
    'DataWizual/sentinel-core': '${admin_repo}',
    'YOUR_SALT_HERE': '${license_salt}',
}
for old, new in replacements.items():
    content = content.replace(old, new)
open('.env', 'w').write(content)
PYEOF

    chmod 600 .env
    ok ".env configured"
else
    ok ".env already exists — skipping configuration"
fi

# =================================================================
# STEP 8 — SENTINEL INIT
# =================================================================
info "Initializing Sentinel..."
source .env 2>/dev/null || true

SENTINEL_LICENSE_KEY="${license_key:-$SENTINEL_LICENSE_KEY}" \
AUDITOR_LICENSE_KEY="${license_key:-$AUDITOR_LICENSE_KEY}" \
"$SENTINEL_BIN" init \
    --token "${alert_token:-$SENTINEL_ALERT_TOKEN}" \
    --repo "${admin_repo:-$SENTINEL_ADMIN_REPO}" \
    && ok "Sentinel initialized" \
    || fail "Sentinel initialization failed. Check your License Key."

# =================================================================
# STEP 9 — PRE-COMMIT HOOK (с полным путём к sentinel)
# =================================================================
if [ -d ".git" ]; then
    info "Installing pre-commit security hook..."

    # Удаляем старые hooks чтобы не было конфликтов
    rm -f .git/hooks/pre-commit .git/hooks/pre-commit.legacy

    cat > .git/hooks/pre-commit << HOOKEOF
#!/bin/bash
SENTINEL="${SENTINEL_BIN}"
echo "🔍 Sentinel is verifying commit security..."
"\${SENTINEL}" scan . || exit 1
HOOKEOF

    chmod +x .git/hooks/pre-commit
    ok "Pre-commit hook installed"
else
    warn "Not a git repository — pre-commit hook skipped"
fi

# =================================================================
# CLEANUP
# =================================================================
unset install_token gemini_key alert_token license_salt
history -c 2>/dev/null || true

# =================================================================
# DONE
# =================================================================
echo ""
echo -e "${BOLD}${GREEN}------------------------------------------------------------"
echo "✅ SENTINEL CORE DEPLOYED SUCCESSFULLY"
echo "------------------------------------------------------------${NC}"
echo ""
echo -e "  Run security scan:  ${YELLOW}${SENTINEL_BIN} scan .${NC}"
echo -e "  Run with report:    ${YELLOW}${SENTINEL_BIN} scan . --report${NC}"
echo -e "  View Machine ID:    ${YELLOW}${SENTINEL_BIN} --id${NC}"
echo ""