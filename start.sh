#!/bin/bash
# =================================================================
# SENTINEL CORE — UNIFIED PROVISIONING SCRIPT
# DataWizual Security (c) 2026
# =================================================================
# Устанавливает и настраивает Sentinel Core + встроенный Auditor
# на рабочей машине клиента.
# Основная часть системы хранится в приватном GitHub репозитории.
# =================================================================

set -e  # Останавливаемся при любой ошибке

# --- Цвета ---
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

# --- Утилиты ---
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
info "Installing/updating dependencies..."
pip install -q --upgrade pip
[ -f "requirements.txt" ] && pip install -q -r requirements.txt
ok "Dependencies installed"

# =================================================================
# STEP 4 — MACHINE ID
# =================================================================
echo ""
info "Detecting Machine ID for license binding..."
MACHINE_ID=$(python3 get_id.py 2>/dev/null || sentinel --id 2>/dev/null || echo "UNKNOWN")
echo ""
echo -e "${BOLD}  Your Machine ID: ${YELLOW}${MACHINE_ID}${NC}"
echo ""
echo "  Send this ID to DataWizual Security to receive your License Key."
echo "  Contact: eldorzufarov66@gmail.com"
echo ""

# =================================================================
# STEP 5 — ENVIRONMENT CONFIGURATION (.env)
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

    read -s -p "  Enter GitHub Alert Token (for Shield reporting): " alert_token
    echo ""
    [ -z "$alert_token" ] && warn "GitHub Alert Token not set. Remote reporting disabled."

    read -p "  Enter Admin Repo [DataWizual/sentinel-core]: " admin_repo
    admin_repo=${admin_repo:-DataWizual/sentinel-core}

    # Записываем значения в .env через Python (безопасно для спецсимволов)
    python3 - << PYEOF
import os
content = open('.env').read()
replacements = {
    'YOUR_LICENSE_KEY_HERE': '${license_key}',
    'YOUR_GEMINI_API_KEY_HERE': '${gemini_key}',
    '<KEY>': '${gemini_key}',
    '<MODEL>': '${gemini_model}',
    'gemini-2.5-flash': '${gemini_model}',
    'YOUR_GITHUB_TOKEN_HERE': '${alert_token}',
    'YourOrg/sentinel-core': '${admin_repo}',
    'DataWizual/sentinel-core': '${admin_repo}',
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
# STEP 6 — INSTALL SENTINEL FROM GITHUB
# =================================================================
echo ""
info "Installing Sentinel Core from GitHub..."

read -p "  Enter Install Token (contents:read PAT): " install_token
if [ -n "$install_token" ]; then
    source .env 2>/dev/null || true
    REPO=${SENTINEL_ADMIN_REPO:-DataWizual/sentinel-core}
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
# STEP 7 — SENTINEL INIT (License binding + config)
# =================================================================
info "Initializing Sentinel..."
source .env 2>/dev/null || true

SENTINEL_LICENSE_KEY="${license_key}" \
AUDITOR_LICENSE_KEY="${license_key}" \
sentinel init \
    --token "${SENTINEL_ALERT_TOKEN}" \
    --repo "${SENTINEL_ADMIN_REPO}" \
    && ok "Sentinel initialized" \
    || fail "Sentinel initialization failed. Check your License Key."

# =================================================================
# STEP 8 — PRE-COMMIT HOOK
# =================================================================
if [ -d ".git" ]; then
    info "Installing pre-commit security hook..."
    pip install -q pre-commit
    pre-commit install && ok "Pre-commit hook installed" || warn "Pre-commit install failed"
else
    warn "Not a git repository — pre-commit hook skipped"
fi

# =================================================================
# CLEANUP
# =================================================================
unset install_token
unset gemini_key
unset alert_token
history -c 2>/dev/null || true

# =================================================================
# DONE
# =================================================================
echo ""
echo -e "${BOLD}${GREEN}------------------------------------------------------------"
echo "✅ SENTINEL CORE DEPLOYED SUCCESSFULLY"
echo "------------------------------------------------------------${NC}"
echo ""
echo -e "  Run security scan:  ${YELLOW}sentinel scan .${NC}"
echo -e "  Run with report:    ${YELLOW}sentinel scan . --report${NC}"
echo -e "  View Machine ID:    ${YELLOW}sentinel --id${NC}"
echo ""