#!/usr/bin/env bash

# ╭──────────────────────────────────────────────────────────────╮
# │  ScanAI Installer — AI-Powered Penetration Testing Agent     │
# │  Version: 0.4.0 · 23 Scanners · 103 Profiles · 9 Chains      │
# │  License: MIT · Kali Linux Only                              │
# ╰──────────────────────────────────────────────────────────────╯

set -euo pipefail
IFS=$' \n\t'

# ── Theme ──────────────────────────────────────────────────────
C_ORANGE='\033[38;5;208m'
C_RED='\033[38;5;196m'
C_CYAN='\033[38;5;81m'
C_GREEN='\033[38;5;82m'
C_WHITE='\033[38;5;255m'
C_GRAY='\033[38;5;244m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ── Progress Bar & Logging ─────────────────────────────────────
step_completed() {
    local custom_msg="${1:-}"
    if [ "${TOTAL_STEPS:-0}" -gt 0 ]; then
        CURRENT_STEP=$((CURRENT_STEP + 1))
        local width=40
        local cur="$CURRENT_STEP"
        [ "$cur" -gt "$TOTAL_STEPS" ] && cur="$TOTAL_STEPS"
        
        local completed=$(( (cur * width) / TOTAL_STEPS ))
        local remaining=$(( width - completed ))
        
        local filled=""
        local empty=""
        local i
        for ((i=0; i<completed; i++)); do filled+="#"; done
        for ((i=0; i<remaining; i++)); do empty+="-"; done
        
        local pct
        pct=$(awk "BEGIN { printf \"%5.2f\", ($cur / $TOTAL_STEPS) * 100 }")
        
        if [ -n "$custom_msg" ]; then
            echo -e "${C_GRAY}│   └─► ${NC}${C_GREEN}${custom_msg}${NC} ${C_GRAY}[${NC}${C_GREEN}${BOLD}${filled}${NC}${C_GRAY}${empty}]${NC} ${C_GREEN}${BOLD}${pct}%${NC}"
        else
            echo -e "${C_GRAY}│   └─► ${NC}${C_GRAY}[${NC}${C_GREEN}${BOLD}${filled}${NC}${C_GRAY}${empty}]${NC} ${C_GREEN}${BOLD}${pct}%${NC}"
        fi
    fi
}

log_banner() {
    clear
    echo -e "${C_WHITE}${BOLD}"
    echo -e "  ░█▀▀░█▀▀░█▀█░█▀█░█▀█░▀█▀"
    echo -e "  ░▀▀█░█░░░█▀█░█░█░█▀█░░█░"
    echo -e "  ░▀▀▀░▀▀▀░▀░▀░▀░▀░▀░▀░▀▀▀"
    echo -e "${NC}"
    echo -e "  ${C_RED}${BOLD}v0.4.0${NC} ${DIM}· AI Hacking Agent · Kali Linux${NC}\n"
}

log_header()  { echo -e "\n${C_ORANGE}${BOLD}▸ $1${NC}"; }
log_step()    { LAST_ACTION="$1"; echo -e "${C_GRAY}┌── ${NC}${BOLD}${C_WHITE}${1}${NC}"; }
log_info()    { LAST_ACTION="$1"; echo -e "${C_GRAY}│   ${NC}${DIM}${1}${NC}"; }
log_ok()      { echo -e "${C_GRAY}│   ${C_GREEN}✓${NC} ${1}"; }
log_skip()    { echo -e "${C_GRAY}│   ${C_CYAN}○${NC} ${DIM}${1} (already installed)${NC}"; }
log_warn()    { echo -e "${C_GRAY}│   ${C_ORANGE}!${NC} ${C_ORANGE}${1}${NC}"; }
log_fail()    { echo -e "${C_GRAY}│   ${C_RED}✕${NC} ${C_RED}${1}${NC}"; }
log_end()     { echo -e "${C_GRAY}╰─────────────────────────────────────────────${NC}\n"; }

# ── Globals ────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
PROJECT_ROOT="${SCRIPT_DIR}"
VENV_DIR="${PROJECT_ROOT}/venv"
SCANAI_USER="${SUDO_USER:-$(logname 2>/dev/null || echo "$(who | awk 'NR==1{print $1}')")}"
SCANAI_HOME="$(eval echo ~"$SCANAI_USER" 2>/dev/null || echo "/home/$SCANAI_USER")"
LOG_FILE="/tmp/scanai_install_$(date +%Y%m%d_%H%M%S).log"
GLOBAL_SCANAI="/usr/local/bin/scanai"
REQUIREMENTS_FILE="${PROJECT_ROOT}/requirements.txt"
INSTALL_SUCCESS=false
LAST_ACTION="Initializing setup"

# ── Cleanup ────────────────────────────────────────────────────
cleanup_handler() {
    local exit_code=$?
    if [ $exit_code -ne 0 ] && [ "$INSTALL_SUCCESS" = false ]; then
        local cur="${CURRENT_STEP:-0}"
        local tot="${TOTAL_STEPS:-60}"
        [ "$tot" -le 0 ] && tot=60
        [ "$cur" -gt "$tot" ] && cur="$tot"
        local pct
        pct=$(awk "BEGIN { printf \"%5.2f\", ($cur / $tot) * 100 }")

        echo -e "${C_RED}│${NC}"
        echo -e "${C_RED}╰─► ✕ INSTALLATION INTERRUPTED / FAILED${NC}"
        echo -e "    ${C_GRAY}╭──────────────────────────────────────────────────────────╮${NC}"
        echo -e "    ${C_GRAY}│${NC} ${C_RED}Error:${NC} Installation stopped prematurely at ${BOLD}${C_ORANGE}${pct}%${NC}"
        echo -e "    ${C_GRAY}│${NC} ${DIM}Step:${NC}  ${cur}/${tot} completed"
        echo -e "    ${C_GRAY}│${NC} ${DIM}Task:${NC}  ${LAST_ACTION}"
        echo -e "    ${C_GRAY}│${NC} ${DIM}Logs:${NC}  ${LOG_FILE}"
        echo -e "    ${C_GRAY}╰──────────────────────────────────────────────────────────╯${NC}"

        [ -d "$VENV_DIR" ] && rm -rf "$VENV_DIR" 2>/dev/null
        [ -L "$GLOBAL_SCANAI" ] && rm -f "$GLOBAL_SCANAI" 2>/dev/null
    elif [ $exit_code -eq 0 ]; then
        rm -f "$LOG_FILE" 2>/dev/null
    fi
    TOTAL_STEPS=0
    return $exit_code
}
trap cleanup_handler EXIT

# ── Helpers ────────────────────────────────────────────────────
cmd_exists()  { command -v "$1" >/dev/null 2>&1; }
pkg_exists()  { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "ok installed"; }

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${C_RED}✕ Root required. Run: sudo ./install.sh setup${NC}"
        exit 1
    fi
    log_ok "Root privileges verified"
    step_completed
}

check_kali() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        if [ "$ID" = "kali" ]; then
            log_ok "Kali Linux OS detected"
            step_completed
            return 0
        fi
    fi
    log_fail "ScanAI requires Kali Linux."
    exit 1
}

# ── Install a package if not present ──────────────────────────
ensure_pkg() {
    local pkg="$1"
    if pkg_exists "$pkg" || cmd_exists "$pkg"; then
        log_skip "$pkg"
    else
        log_info "Installing $pkg..."
        if DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$pkg" >> "$LOG_FILE" 2>&1; then
            log_ok "$pkg"
        else
            log_warn "Failed to install $pkg (non-critical)"
        fi
    fi
    step_completed
}

# ── Install a Go tool if not present ─────────────────────────
ensure_go_tool() {
    local name="$1"
    local pkg="$2"
    local gobin="$SCANAI_HOME/go/bin"

    # Check global PATH and user's GOBIN
    if cmd_exists "$name" || [ -x "$gobin/$name" ]; then
        # Ensure symlink exists even if binary is already in GOBIN
        [ -x "$gobin/$name" ] && [ ! -e "/usr/local/bin/$name" ] && \
            ln -sf "$gobin/$name" "/usr/local/bin/$name" 2>/dev/null
        log_skip "$name"
    else
        log_info "Installing $name via go install..."
        if su - "$SCANAI_USER" -c "GOBIN='$gobin' go install -v $pkg" >> "$LOG_FILE" 2>&1; then
            # Symlink to /usr/local/bin so it's globally available
            if [ -x "$gobin/$name" ]; then
                ln -sf "$gobin/$name" "/usr/local/bin/$name"
                log_ok "$name → /usr/local/bin/$name"
            else
                log_ok "$name (installed to GOBIN)"
            fi
        else
            log_warn "Failed to install $name"
        fi
    fi
    step_completed
}

# ── Install Titus (secrets scanner) from GitHub releases ──────
install_titus() {
    log_step "Titus (Secrets Scanner)"

    if cmd_exists titus; then
        log_skip "titus"
        step_completed
        log_end
        return 0
    fi

    local arch
    arch="$(uname -m)"
    local binary_name=""

    case "$arch" in
        x86_64)  binary_name="titus-linux-amd64" ;;
        aarch64) binary_name="titus-linux-arm64" ;;
        *)
            log_warn "Unsupported architecture: $arch — skipping titus"
            step_completed
            log_end
            return 0
            ;;
    esac

    log_info "Fetching latest release from github.com/praetorian-inc/titus..."

    # Get latest release download URL
    local download_url
    download_url=$(curl -sL "https://api.github.com/repos/praetorian-inc/titus/releases/latest" \
        | grep "browser_download_url.*${binary_name}\"" \
        | head -1 \
        | cut -d '"' -f 4)

    if [ -z "$download_url" ]; then
        log_warn "Could not find titus release for $binary_name"
        log_info "Install manually: https://github.com/praetorian-inc/titus/releases"
        step_completed
        log_end
        return 0
    fi

    log_info "Downloading $binary_name..."
    local tmp_bin="/tmp/titus_$$"

    if curl -sL "$download_url" -o "$tmp_bin" >> "$LOG_FILE" 2>&1; then
        chmod +x "$tmp_bin"
        mv "$tmp_bin" /usr/local/bin/titus
        chown root:root /usr/local/bin/titus
        log_ok "titus installed → /usr/local/bin/titus"
    else
        log_warn "Failed to download titus"
        rm -f "$tmp_bin" 2>/dev/null
    fi

    step_completed
    log_end
}

# ── System Dependencies ───────────────────────────────────────
install_system_deps() {
    log_step "System Dependencies"

    log_info "Updating apt repositories..."
    apt-get update -qq >> "$LOG_FILE" 2>&1 || log_warn "Some repos failed to update"
    step_completed

    # Core
    ensure_pkg git
    ensure_pkg curl
    ensure_pkg wget
    ensure_pkg net-tools
    ensure_pkg gcc
    ensure_pkg build-essential
    ensure_pkg libssl-dev
    ensure_pkg libffi-dev
    ensure_pkg python3-dev

    # Python
    ensure_pkg python3
    ensure_pkg python3-pip
    ensure_pkg python3-venv

    # Go
    ensure_pkg golang-go

    # Security tools
    local sec_tools=(
        nmap nikto whatweb wafw00f wpscan enum4linux
        sqlmap theharvester sslyze dnsenum dnsrecon
        seclists
    )
    for tool in "${sec_tools[@]}"; do
        ensure_pkg "$tool"
    done

    log_end
}

# ── Go-based Tools ─────────────────────────────────────────────
install_go_tools() {
    log_step "Go-based Security Tools"

    if ! cmd_exists go; then
        log_warn "Go not available — skipping Go tools"
        CURRENT_STEP=$((CURRENT_STEP + 5))
        draw_progress
        log_end
        return 0
    fi

    ensure_go_tool nuclei   "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    ensure_go_tool dalfox   "github.com/hahwul/dalfox/v2@latest"
    ensure_go_tool httpx    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    ensure_go_tool katana   "github.com/projectdiscovery/katana/cmd/katana@latest"

    # Ensure GOBIN in user's .bashrc for interactive shells
    local bashrc="$SCANAI_HOME/.bashrc"
    if [ -f "$bashrc" ] && ! grep -q "GOBIN" "$bashrc"; then
        echo -e '\n# Go Binaries\nexport GOBIN=$HOME/go/bin\nexport PATH=$PATH:$GOBIN' >> "$bashrc"
        log_ok "Added GOBIN to .bashrc"
    fi

    # Symlink any Go binaries not yet in /usr/local/bin
    local gobin="$SCANAI_HOME/go/bin"
    if [ -d "$gobin" ]; then
        for bin in "$gobin"/*; do
            [ -x "$bin" ] || continue
            local bname
            bname="$(basename "$bin")"
            if [ ! -e "/usr/local/bin/$bname" ]; then
                ln -sf "$bin" "/usr/local/bin/$bname"
            fi
        done
    fi

    step_completed
    log_end
}

# ── Python Virtual Environment ─────────────────────────────────
setup_venv() {
    log_step "Python Virtual Environment"

    if [ -d "$VENV_DIR" ]; then
        log_warn "Removing existing venv..."
        rm -rf "$VENV_DIR"
    fi

    log_info "Creating venv..."
    if su - "$SCANAI_USER" -c "cd '$PROJECT_ROOT' && python3 -m venv '$VENV_DIR' --without-pip" >> "$LOG_FILE" 2>&1; then
        log_ok "Venv created at $VENV_DIR"
        step_completed
    else
        log_fail "Failed to create venv"
        return 1
    fi

    log_info "Installing pip..."
    if su - "$SCANAI_USER" -c "wget -qO /tmp/get-pip.py https://bootstrap.pypa.io/get-pip.py && '$VENV_DIR/bin/python' /tmp/get-pip.py" >> "$LOG_FILE" 2>&1; then
        log_ok "pip installed"
        rm -f /tmp/get-pip.py
        step_completed
    else
        log_fail "Failed to install pip"
        return 1
    fi

    log_end
}

# ── Python Dependencies ────────────────────────────────────────
install_python_deps() {
    log_step "Python Dependencies"

    if [ ! -f "$REQUIREMENTS_FILE" ]; then
        log_fail "requirements.txt not found"
        return 1
    fi

    log_info "Upgrading pip..."
    su - "$SCANAI_USER" -c "source '$VENV_DIR/bin/activate' && pip install --upgrade pip" >> "$LOG_FILE" 2>&1
    step_completed

    log_info "Installing requirements..."
    if su - "$SCANAI_USER" -c "source '$VENV_DIR/bin/activate' && pip install -r '$REQUIREMENTS_FILE'" >> "$LOG_FILE" 2>&1; then
        log_ok "Requirements installed"
        step_completed
    else
        log_fail "Failed to install requirements"
        return 1
    fi

    log_info "Installing ScanAI (editable)..."
    if su - "$SCANAI_USER" -c "source '$VENV_DIR/bin/activate' && pip install -e '$PROJECT_ROOT'" >> "$LOG_FILE" 2>&1; then
        log_ok "ScanAI installed in dev mode"
        step_completed
    else
        log_fail "Failed to install ScanAI"
        return 1
    fi

    log_end
}

# ── Global Command ─────────────────────────────────────────────
setup_global_command() {
    log_step "Global Command"

    local scanai_bin="${VENV_DIR}/bin/scanai"
    if [ ! -x "$scanai_bin" ]; then
        log_warn "ScanAI binary not found at $scanai_bin"
        step_completed
        log_end
        return 1
    fi

    [ -L "$GLOBAL_SCANAI" ] || [ -f "$GLOBAL_SCANAI" ] && rm -f "$GLOBAL_SCANAI"

    if ln -sf "$scanai_bin" "$GLOBAL_SCANAI"; then
        log_ok "scanai → $scanai_bin"
    else
        log_fail "Failed to create symlink"
    fi
    step_completed

    log_end
}

# ── Permissions ────────────────────────────────────────────────
set_permissions() {
    log_step "Permissions"
    chown -R "$SCANAI_USER:$SCANAI_USER" "$PROJECT_ROOT" 2>/dev/null
    log_ok "Ownership set to $SCANAI_USER"
    step_completed
    log_end
}

# ── Verify ─────────────────────────────────────────────────────
verify_installation() {
    log_step "Verification"

    if sudo -u "$SCANAI_USER" "$VENV_DIR/bin/python" -c "import scanai" > /dev/null 2>&1; then
        log_ok "ScanAI module import OK"
    else
        log_fail "ScanAI module import failed"
        step_completed
        return 1
    fi
    step_completed

    # Check key packages
    local pkgs=("requests" "rich" "dotenv:python-dotenv" "langchain_google_genai:langchain-google-genai" "dns:dnspython" "aiohttp" "yaml:pyyaml")
    for entry in "${pkgs[@]}"; do
        local import_name="${entry%%:*}"
        local display_name="${entry##*:}"
        if sudo -u "$SCANAI_USER" "$VENV_DIR/bin/python" -c "import $import_name" 2>/dev/null; then
            log_ok "$display_name"
        else
            log_fail "Missing: $display_name"
        fi
        step_completed
    done

    # Check security tools
    local tools=(nmap nuclei dalfox katana nikto sqlmap whatweb wafw00f wpscan enum4linux titus)
    local found=0 total=${#tools[@]}
    for tool in "${tools[@]}"; do
        if cmd_exists "$tool"; then
            found=$((found + 1))
            log_ok "$tool available"
        else
            log_warn "$tool not found in PATH"
        fi
        step_completed
    done
    log_ok "$found/$total security tools available"

    log_end
}

# ── Summary ────────────────────────────────────────────────────
show_summary() {
    echo -e "\n${C_GRAY}╭──────────────────────────────────────────────────────────────╮${NC}"
    echo -e "${C_GRAY}│${NC}  ${BOLD}${C_WHITE}ScanAI${NC}  ${DIM}v0.4.0 · AI Penetration Testing Agent${NC}               ${C_GRAY}│${NC}"
    echo -e "${C_GRAY}│${NC}  ${DIM}23 scanners · 106 profiles · 9 attack chains${NC}                ${C_GRAY}│${NC}"
    echo -e "${C_GRAY}╰──────────────────────────────────────────────────────────────╯${NC}\n"

    echo -e "  ${DIM}Project${NC}     ${C_GREEN}${PROJECT_ROOT}${NC}"
    echo -e "  ${DIM}Venv${NC}        ${C_GREEN}${VENV_DIR}${NC}"
    echo -e "  ${DIM}User${NC}        ${C_GREEN}${SCANAI_USER}${NC}"
    echo -e "  ${DIM}Command${NC}     ${C_GREEN}scanai${NC}"

    echo -e "\n  ${C_CYAN}Quick Start:${NC}"
    echo -e "  ${C_GREEN}1.${NC} scanai config --init    ${DIM}# set API keys${NC}"
    echo -e "  ${C_GREEN}2.${NC} scanai config --check   ${DIM}# verify config${NC}"
    echo -e "  ${C_GREEN}3.${NC} scanai start             ${DIM}# launch${NC}"

    echo -e "\n${C_GREEN}✓ Installation complete.${NC}\n"
}

# ── Launch Shell ───────────────────────────────────────────────
launch_scanai_shell() {
    # Create unique temp bashrc
    local TEMP_BASHRC="/tmp/scanai_bashrc_${SCANAI_USER}_$(date +%s)_$$"

    local bashrc_content
    bashrc_content=$(cat << 'EOF'
# ScanAI Environment - Temporary Configuration
SCANAI_ORIGINAL_PS1="$PS1"

if [ -f "VENV_DIR/bin/activate" ]; then
    source "VENV_DIR/bin/activate"
    export VIRTUAL_ENV_DISABLE_PROMPT=1
    export PS1="(scanai) $SCANAI_ORIGINAL_PS1"

    echo -e "\n\033[0;36m◆ SCANAI\033[0m  \033[2mv0.4.0 · AI Hacking Agent\033[0m"
    echo -e "\033[2m──────────────────────────────────────────────\033[0m"
    echo -e "\033[0;32m  Virtual environment activated.\033[0m\n"
    echo -e "\033[0;36m▸ COMMANDS\033[0m"
    echo -e "  scanai start     Start interactive scanner"
    echo -e "  scanai config    View/modify configuration"
    echo -e "  scanai --help    Show all commands"
    echo -e "  deactivate       Exit virtual environment"
    echo

    scanai_deactivate() {
        export PS1="$SCANAI_ORIGINAL_PS1"
        unset SCANAI_ORIGINAL_PS1
        unset VIRTUAL_ENV_DISABLE_PROMPT
        unset -f scanai_deactivate 2>/dev/null
        deactivate
        echo -e "\033[1;32m✅ ScanAI environment deactivated.\033[0m"
        [ -f "TEMP_FILE" ] && rm -f "TEMP_FILE"
    }
    alias deactivate=scanai_deactivate
else
    echo -e "\033[1;31m❌ Error: Virtual environment not found at VENV_DIR\033[0m"
    echo "Please run the installer again."
    exit 1
fi
EOF
)

    # Replace placeholders
    bashrc_content="${bashrc_content//VENV_DIR/$VENV_DIR}"
    bashrc_content="${bashrc_content//TEMP_FILE/$TEMP_BASHRC}"

    echo "$bashrc_content" > "$TEMP_BASHRC"
    chown "$SCANAI_USER:$SCANAI_USER" "$TEMP_BASHRC"
    chmod 644 "$TEMP_BASHRC"

    echo -e "\n${C_GREEN}Launching ScanAI shell...${NC}"
    echo -e "${DIM}Type 'exit' to return to your normal shell.${NC}"
    echo -e "\n${C_CYAN}Press Enter to continue...${NC}"
    read -r

    exec sudo -u "$SCANAI_USER" bash --rcfile "$TEMP_BASHRC"
}

# ── Post-install Options ──────────────────────────────────────
post_install_options() {
    echo -e "${C_CYAN}  1)${NC} Launch ScanAI shell (venv activated)"
    echo -e "${C_CYAN}  2)${NC} Show activation commands"
    echo -e "${C_CYAN}  3)${NC} Exit\n"

    while true; do
        echo -e -n "${C_CYAN}  Choice (1-3): ${NC}"
        read -r choice
        case "$choice" in
            1)
                launch_scanai_shell
                break
                ;;
            2)
                echo -e "\n  ${C_GREEN}source $VENV_DIR/bin/activate${NC}"
                echo -e "  ${C_GREEN}scanai start${NC}\n"
                break
                ;;
            3) break ;;
            *) echo -e "  ${C_RED}Invalid choice${NC}" ;;
        esac
    done
}

# ── Usage ──────────────────────────────────────────────────────
show_usage() {
    log_banner
    echo -e "  ${C_CYAN}Usage:${NC} sudo ./install.sh ${C_ORANGE}[setup|launch]${NC}\n"
    echo -e "  ${C_GREEN}setup${NC}    Full installation"
    echo -e "  ${C_GREEN}launch${NC}   Activate environment\n"
    INSTALL_SUCCESS=true
}

# ── Main ───────────────────────────────────────────────────────
run_setup() {
    TOTAL_STEPS=60
    CURRENT_STEP=0

    log_banner
    log_header "INSTALLATION"
    log_info "User: $SCANAI_USER · Log: $LOG_FILE"

    check_root
    check_kali
    install_system_deps
    install_go_tools
    install_titus
    setup_venv
    install_python_deps
    setup_global_command
    set_permissions
    verify_installation

    INSTALL_SUCCESS=true
    
    echo -e "${C_GREEN}│${NC}"
    echo -e "${C_GREEN}╰─► ✓ PROGRESS COMPLETION REPORT${NC}"
    echo -e "    ${C_GRAY}╭──────────────────────────────────────────────────────────╮${NC}"
    echo -e "    ${C_GRAY}│${NC} ${C_GREEN}Status:${NC} Installation successfully reached ${BOLD}${C_GREEN}100.00%${NC}"
    echo -e "    ${C_GRAY}│${NC} ${DIM}Steps:${NC}  ${CURRENT_STEP}/${TOTAL_STEPS} discrete build operations executed"
    echo -e "    ${C_GRAY}│${NC} ${DIM}Result:${NC} Ready for AI Penetration Testing Agent deployment"
    echo -e "    ${C_GRAY}╰──────────────────────────────────────────────────────────╯${NC}\n"

    TOTAL_STEPS=0
    show_summary
    post_install_options
}

# ── Entry ──────────────────────────────────────────────────────
if [[ $# -eq 0 ]]; then
    show_usage
    exit 0
fi

case "$1" in
    setup)  run_setup ;;
    launch)
        check_root
        post_install_options
        ;;
    *) show_usage; exit 1 ;;
esac
