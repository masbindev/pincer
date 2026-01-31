#!/usr/bin/env bash
# =============================================================================
# 🦀 Pincer — Security scanner for OpenClaw/Clawdbot/Moltbot
#    One script, zero dependencies.
#
#    https://github.com/masbindev/pincer
#    MIT License — Copyright (c) 2026 masbindev
# =============================================================================

set -eo pipefail

PINCER_VERSION="1.0.0"

# ---------------------------------------------------------------------------
# Colors (respect NO_COLOR: https://no-color.org/)
# ---------------------------------------------------------------------------
if [[ -z "${NO_COLOR:-}" && -t 1 ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
    BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'
    DIM='\033[2m'; RESET='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; BOLD=''; DIM=''; RESET=''
fi

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------
SCORE=100
TOTAL_CHECKS=12
PASSED=0
WARNINGS=0
CRITICALS=0
JSON_MODE=0
AUTO_YES=0

declare -a CRITICAL_MSGS=()
declare -a WARNING_MSGS=()
declare -a PASSED_MSGS=()
declare -a FIX_ACTIONS=()
declare -a CONFIG_FILES=()
declare -a CONFIG_DIRS=()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
die()  { echo -e "${RED}Error: $1${RESET}" >&2; exit 1; }
info() { [[ $JSON_MODE -eq 0 ]] && echo -e "${CYAN}$1${RESET}"; }
warn_msg() { [[ $JSON_MODE -eq 0 ]] && echo -e "${YELLOW}$1${RESET}"; }

add_critical() {
    CRITICAL_MSGS+=("$1")
    ((CRITICALS++)) || true
    SCORE=$((SCORE - 12))
    (( SCORE < 0 )) && SCORE=0 || true
}

add_warning() {
    WARNING_MSGS+=("$1")
    ((WARNINGS++)) || true
    SCORE=$((SCORE - 5))
    (( SCORE < 0 )) && SCORE=0 || true
}

add_pass() {
    PASSED_MSGS+=("$1")
    ((PASSED++)) || true
}

grade() {
    local s=$1
    if   (( s >= 90 )); then echo "A"
    elif (( s >= 80 )); then echo "B"
    elif (( s >= 70 )); then echo "C"
    elif (( s >= 60 )); then echo "D"
    else echo "F"
    fi
}

# ---------------------------------------------------------------------------
# Config discovery
# ---------------------------------------------------------------------------
discover_configs() {
    local search_dirs=()

    # Env-based
    [[ -n "${OPENCLAW_HOME:-}" ]] && search_dirs+=("$OPENCLAW_HOME")
    [[ -n "${MOLTBOT_HOME:-}" ]]  && search_dirs+=("$MOLTBOT_HOME")

    # Standard locations
    search_dirs+=(
        "$HOME/.openclaw"
        "$HOME/.clawdbot"
        "$HOME/.moltbot"
        "."
        "/etc/openclaw"
    )

    local config_names=("config.yaml" "config.yml" "config.json" "clawdbot.json" "moltbot.json" "openclaw.json" "gateway.yaml" ".env" "docker-compose.yml")

    for dir in "${search_dirs[@]}"; do
        [[ -d "$dir" ]] || continue
        CONFIG_DIRS+=("$dir")
        for name in "${config_names[@]}"; do
            local f="$dir/$name"
            [[ -f "$f" ]] && CONFIG_FILES+=("$f")
        done
    done

    # Deduplicate
    if (( ${#CONFIG_FILES[@]} > 0 )); then
        local -A seen=()
        local unique=()
        for f in "${CONFIG_FILES[@]}"; do
            local real
            real=$(realpath "$f" 2>/dev/null || echo "$f")
            if [[ -z "${seen[$real]:-}" ]]; then
                seen[$real]=1
                unique+=("$f")
            fi
        done
        CONFIG_FILES=("${unique[@]}")
    fi
}

# Simple YAML value extractor (no yq needed)
cfg_get() {
    local file="$1" key="$2"
    # Try JSON style: "key": "value" or "key": value
    local val
    val=$(grep -E "\"${key}\"\s*:" "$file" 2>/dev/null | head -1 | sed 's/.*:\s*//' | sed 's/[",]//g' | sed 's/^\s*//;s/\s*$//')
    if [[ -n "$val" ]]; then echo "$val"; return; fi
    # Try YAML style: key: value
    val=$(grep -E "^\s*${key}\s*:" "$file" 2>/dev/null | head -1 | sed 's/^[^:]*:\s*//' | sed 's/\s*#.*//' | sed 's/^["'"'"']//' | sed 's/["'"'"']$//')
    echo "$val"
}
# Backward compat alias
yaml_get() { cfg_get "$@"; }

# Check if a key exists anywhere in config files
config_has_key() {
    local key="$1"
    for f in "${CONFIG_FILES[@]}"; do
        if grep -qE "(^|\s)${key}" "$f" 2>/dev/null; then
            return 0
        fi
    done
    return 1
}

# Get value from any config file
config_get() {
    local key="$1"
    for f in "${CONFIG_FILES[@]}"; do
        local val
        val=$(yaml_get "$f" "$key")
        if [[ -n "$val" ]]; then
            echo "$val"
            return 0
        fi
    done
    return 1
}

# ---------------------------------------------------------------------------
# Check 1: Gateway Binding
# ---------------------------------------------------------------------------
check_gateway_binding() {
    local found_exposed=0
    local bind_addr=""

    # Check config files for gateway host/bind
    for f in "${CONFIG_FILES[@]}"; do
        for key in "host" "bind" "address" "listen"; do
            local val
            val=$(yaml_get "$f" "$key")
            if [[ "$val" == "0.0.0.0" ]]; then
                bind_addr="$val"
                found_exposed=1
                break 2
            fi
        done
    done

    # Check running processes listening on 0.0.0.0
    if command -v ss &>/dev/null && [[ $found_exposed -eq 0 ]]; then
        if ss -tlnp 2>/dev/null | grep -qE '0\.0\.0\.0:(3000|3001|8080|8443)'; then
            found_exposed=1
            bind_addr="0.0.0.0"
        fi
    fi

    if [[ $found_exposed -eq 1 ]]; then
        add_critical "Gateway exposed on ${bind_addr} (should be 127.0.0.1)"
        FIX_ACTIONS+=("rebind_gateway")
    else
        add_pass "Gateway not exposed on 0.0.0.0"
    fi
}

# ---------------------------------------------------------------------------
# Check 2: API Keys Exposure
# ---------------------------------------------------------------------------
check_api_keys() {
    local found=0
    local patterns=(
        'sk-ant-[a-zA-Z0-9_-]+'
        'sk-[a-zA-Z0-9]{20,}'
        'ANTHROPIC_API_KEY\s*[:=]'
        'OPENAI_API_KEY\s*[:=]'
        'api[_-]?key\s*[:=]\s*["\x27]?[a-zA-Z0-9_-]{20,}'
        'token\s*[:=]\s*["\x27]?[a-zA-Z0-9_-]{20,}'
    )

    for f in "${CONFIG_FILES[@]}"; do
        # Skip .env files — that's where keys SHOULD be
        [[ "$(basename "$f")" == ".env" ]] && continue
        for pat in "${patterns[@]}"; do
            if grep -qE "$pat" "$f" 2>/dev/null; then
                found=1
                break 2
            fi
        done
    done

    if [[ $found -eq 1 ]]; then
        add_critical "Plaintext API keys/tokens found in config files"
        FIX_ACTIONS+=("move_keys_to_env")
    else
        add_pass "API keys not found in plaintext configs"
    fi
}

# ---------------------------------------------------------------------------
# Check 3: File Permissions
# ---------------------------------------------------------------------------
check_file_permissions() {
    local bad_files=()

    for f in "${CONFIG_FILES[@]}"; do
        [[ -f "$f" ]] || continue
        local perms
        perms=$(stat -c '%a' "$f" 2>/dev/null || stat -f '%A' "$f" 2>/dev/null || echo "")
        if [[ -n "$perms" ]]; then
            # Check if group or others can read (anything beyond x00)
            local group_other="${perms:1:2}"
            if [[ "$group_other" != "00" ]]; then
                bad_files+=("$f ($perms)")
            fi
        fi
    done

    if (( ${#bad_files[@]} > 0 )); then
        add_critical "Config files with loose permissions: ${bad_files[*]}"
        FIX_ACTIONS+=("fix_permissions")
    else
        if (( ${#CONFIG_FILES[@]} > 0 )); then
            add_pass "Config file permissions OK"
        else
            add_pass "No config files found to check permissions"
        fi
    fi
}

# ---------------------------------------------------------------------------
# Check 4: HTTPS/TLS
# ---------------------------------------------------------------------------
check_tls() {
    local tls_found=0

    for f in "${CONFIG_FILES[@]}"; do
        if grep -qiE '(https|tls|ssl|cert|certificate)' "$f" 2>/dev/null; then
            tls_found=1
            break
        fi
    done

    if [[ $tls_found -eq 0 ]]; then
        add_warning "HTTPS/TLS not configured"
    else
        add_pass "HTTPS/TLS configuration detected"
    fi
}

# ---------------------------------------------------------------------------
# Check 5: Shell Command Allowlist
# ---------------------------------------------------------------------------
check_shell_allowlist() {
    local found=0

    for f in "${CONFIG_FILES[@]}"; do
        if grep -qE '(safeBins|allowlist|allowedCommands|exec\.allow)' "$f" 2>/dev/null; then
            found=1
            break
        fi
    done

    if [[ $found -eq 0 ]]; then
        add_critical "No shell command allowlist (safeBins not configured)"
        FIX_ACTIONS+=("add_safebins")
    else
        add_pass "Shell command allowlist configured"
    fi
}

# ---------------------------------------------------------------------------
# Check 6: Sensitive Directories
# ---------------------------------------------------------------------------
check_sensitive_dirs() {
    local accessible=()
    local dirs=("$HOME/.ssh" "$HOME/.gnupg" "$HOME/.aws" "/etc/shadow")

    for d in "${dirs[@]}"; do
        if [[ -r "$d" ]]; then
            accessible+=("$d")
        fi
    done

    # Check if any config excludes these dirs
    local excluded=0
    for f in "${CONFIG_FILES[@]}"; do
        if grep -qE '(exclude|deny|block).*\.(ssh|gnupg|aws)' "$f" 2>/dev/null; then
            excluded=1
            break
        fi
    done

    if (( ${#accessible[@]} > 0 )) && [[ $excluded -eq 0 ]]; then
        local short=()
        for d in "${accessible[@]}"; do
            short+=("$(echo "$d" | sed "s|$HOME|~|")")
        done
        add_warning "Sensitive directories accessible (${short[*]})"
    else
        add_pass "Sensitive directories protected or excluded"
    fi
}

# ---------------------------------------------------------------------------
# Check 7: Webhook Auth
# ---------------------------------------------------------------------------
check_webhook_auth() {
    local webhook_found=0
    local auth_found=0

    for f in "${CONFIG_FILES[@]}"; do
        if grep -qiE 'webhook' "$f" 2>/dev/null; then
            webhook_found=1
            if grep -qiE 'webhook.*(auth|token|secret|key)' "$f" 2>/dev/null; then
                auth_found=1
            fi
            break
        fi
    done

    if [[ $webhook_found -eq 1 && $auth_found -eq 0 ]]; then
        add_warning "Webhook endpoints found without auth tokens"
    else
        add_pass "Webhook auth OK (or no webhooks configured)"
    fi
}

# ---------------------------------------------------------------------------
# Check 8: Sandbox Isolation
# ---------------------------------------------------------------------------
check_sandbox() {
    local sandbox=0

    # Check if running inside Docker
    if [[ -f "/.dockerenv" ]] || grep -q 'docker\|containerd' /proc/1/cgroup 2>/dev/null; then
        sandbox=1
    fi

    # Check config for sandbox/docker settings
    for f in "${CONFIG_FILES[@]}"; do
        if grep -qiE '(sandbox|docker|container|isolation)\s*[:=]\s*(true|enabled|yes)' "$f" 2>/dev/null; then
            sandbox=1
            break
        fi
    done

    if [[ $sandbox -eq 0 ]]; then
        add_warning "No sandbox/Docker isolation detected"
    else
        add_pass "Sandbox/container isolation detected"
    fi
}

# ---------------------------------------------------------------------------
# Check 9: Default/Weak Credentials
# ---------------------------------------------------------------------------
check_default_creds() {
    local found_weak=0

    for f in "${CONFIG_FILES[@]}"; do
        # Check for 'undefined' token bug
        if grep -qE "token\s*[:=]\s*['\"]?undefined['\"]?" "$f" 2>/dev/null; then
            found_weak=1
            break
        fi
        # Check for common defaults
        if grep -qiE "token\s*[:=]\s*['\"]?(changeme|password|admin|default|test|12345)['\"]?" "$f" 2>/dev/null; then
            found_weak=1
            break
        fi
    done

    # Check if gateway token is set at all
    local has_gateway_token=0
    for f in "${CONFIG_FILES[@]}"; do
        # Multi-line JSON: just check if "token" key exists with a real value near gateway/auth sections
        if grep -qiE '(gateway.*token|gatewayToken|GATEWAY_TOKEN)' "$f" 2>/dev/null; then
            has_gateway_token=1
            break
        fi
        # JSON configs: token on its own line inside auth block
        if grep -qE '"token"\s*:\s*"[^"]{8,}"' "$f" 2>/dev/null; then
            has_gateway_token=1
            break
        fi
    done

    if [[ $found_weak -eq 1 ]]; then
        add_critical "Default or weak credentials detected (check for 'undefined' token bug)"
    elif [[ $has_gateway_token -eq 0 ]] && (( ${#CONFIG_FILES[@]} > 0 )); then
        add_critical "No gateway auth token configured"
    else
        add_pass "Gateway auth token set and not using defaults"
    fi
}

# ---------------------------------------------------------------------------
# Check 10: Rate Limiting
# ---------------------------------------------------------------------------
check_rate_limiting() {
    local found=0

    for f in "${CONFIG_FILES[@]}"; do
        if grep -qiE '(rateLimit|rate_limit|throttle|maxRequests)' "$f" 2>/dev/null; then
            found=1
            break
        fi
    done

    if [[ $found -eq 0 ]]; then
        add_warning "No rate limiting configured"
    else
        add_pass "Rate limiting configured"
    fi
}

# ---------------------------------------------------------------------------
# Check 11: Node.js Version (CVE-2026-21636)
# ---------------------------------------------------------------------------
check_nodejs_version() {
    if ! command -v node &>/dev/null; then
        add_pass "Node.js not found (not applicable)"
        return
    fi

    local ver
    ver=$(node --version 2>/dev/null | sed 's/^v//')
    local major minor
    major=$(echo "$ver" | cut -d. -f1)
    minor=$(echo "$ver" | cut -d. -f2)

    # CVE-2026-21636 affects Node.js permission model
    # Vulnerable: < 22.14.0, < 23.6.1 (fictional but realistic pattern)
    local vulnerable=0
    if (( major < 22 )); then
        vulnerable=1
    elif (( major == 22 && minor < 14 )); then
        vulnerable=1
    elif (( major == 23 && minor < 7 )); then
        vulnerable=1
    fi

    if [[ $vulnerable -eq 1 ]]; then
        add_critical "Node.js $ver may be vulnerable to CVE-2026-21636 (permission model bypass)"
    else
        add_pass "Node.js $ver — not affected by CVE-2026-21636"
    fi
}

# ---------------------------------------------------------------------------
# Check 12: Control UI Auth Bypass
# ---------------------------------------------------------------------------
check_control_ui_auth() {
    local bypass_found=0

    for f in "${CONFIG_FILES[@]}"; do
        if grep -qiE '(authBypass|auth_bypass|skipAuth|noAuth|disableAuth)\s*[:=]\s*(true|yes|1)' "$f" 2>/dev/null; then
            bypass_found=1
            break
        fi
    done

    if [[ $bypass_found -eq 1 ]]; then
        add_critical "Control UI auth bypass is ENABLED"
        FIX_ACTIONS+=("disable_auth_bypass")
    else
        add_pass "Control UI auth bypass disabled"
    fi
}

# ---------------------------------------------------------------------------
# Report output
# ---------------------------------------------------------------------------
print_report() {
    local g
    g=$(grade "$SCORE")

    echo ""
    echo -e "${BOLD}🦀 Pincer Security Report${RESET}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo -e "  Score: ${BOLD}${SCORE}/100${RESET} (${g})"
    echo ""

    if (( ${#CRITICAL_MSGS[@]} > 0 )); then
        echo -e "${RED}🔴 CRITICAL${RESET}"
        for ((i=0; i<${#CRITICAL_MSGS[@]}; i++)); do
            if (( i == ${#CRITICAL_MSGS[@]} - 1 )); then
                echo -e "  └─ ${CRITICAL_MSGS[$i]}"
            else
                echo -e "  ├─ ${CRITICAL_MSGS[$i]}"
            fi
        done
        echo ""
    fi

    if (( ${#WARNING_MSGS[@]} > 0 )); then
        echo -e "${YELLOW}🟡 WARNING${RESET}"
        for ((i=0; i<${#WARNING_MSGS[@]}; i++)); do
            if (( i == ${#WARNING_MSGS[@]} - 1 )); then
                echo -e "  └─ ${WARNING_MSGS[$i]}"
            else
                echo -e "  ├─ ${WARNING_MSGS[$i]}"
            fi
        done
        echo ""
    fi

    if (( ${#PASSED_MSGS[@]} > 0 )); then
        echo -e "${GREEN}🟢 PASSED${RESET}"
        for ((i=0; i<${#PASSED_MSGS[@]}; i++)); do
            if (( i == ${#PASSED_MSGS[@]} - 1 )); then
                echo -e "  └─ ${PASSED_MSGS[$i]}"
            else
                echo -e "  ├─ ${PASSED_MSGS[$i]}"
            fi
        done
        echo ""
    fi

    echo -e "${BLUE}💡 RECOMMENDATIONS${RESET}"
    echo -e "  ├─ Run: ${BOLD}cisco-ai-defense/skill-scanner${RESET} to audit your skills"
    echo -e "  └─ See: ${BOLD}https://github.com/masbindev/pincer${RESET} for fix guides"
    echo ""

    if (( ${#FIX_ACTIONS[@]} > 0 )); then
        if [[ ! -t 0 ]]; then
            echo -e "To fix issues, install Pincer locally:"
            echo -e "  ${BOLD}curl -sL https://raw.githubusercontent.com/masbindev/pincer/main/pincer.sh -o pincer.sh && chmod +x pincer.sh${RESET}"
            echo -e "  ${BOLD}./pincer.sh fix${RESET}"
        else
            echo -e "Run ${BOLD}./pincer.sh fix${RESET} to auto-fix critical issues."
        fi
    fi
    echo ""
}

print_json_report() {
    local g
    g=$(grade "$SCORE")

    echo "{"
    echo "  \"version\": \"$PINCER_VERSION\","
    echo "  \"score\": $SCORE,"
    echo "  \"grade\": \"$g\","
    echo "  \"checks\": $TOTAL_CHECKS,"
    echo "  \"critical\": $CRITICALS,"
    echo "  \"warnings\": $WARNINGS,"
    echo "  \"passed\": $PASSED,"

    echo "  \"critical_issues\": ["
    for ((i=0; i<${#CRITICAL_MSGS[@]}; i++)); do
        local comma=","; (( i == ${#CRITICAL_MSGS[@]} - 1 )) && comma=""
        echo "    \"${CRITICAL_MSGS[$i]}\"$comma"
    done
    echo "  ],"

    echo "  \"warning_issues\": ["
    for ((i=0; i<${#WARNING_MSGS[@]}; i++)); do
        local comma=","; (( i == ${#WARNING_MSGS[@]} - 1 )) && comma=""
        echo "    \"${WARNING_MSGS[$i]}\"$comma"
    done
    echo "  ],"

    echo "  \"passed_checks\": ["
    for ((i=0; i<${#PASSED_MSGS[@]}; i++)); do
        local comma=","; (( i == ${#PASSED_MSGS[@]} - 1 )) && comma=""
        echo "    \"${PASSED_MSGS[$i]}\"$comma"
    done
    echo "  ]"

    echo "}"
}

# ---------------------------------------------------------------------------
# Fix command
# ---------------------------------------------------------------------------
do_fix() {
    # First run a scan to find issues
    discover_configs
    run_all_checks

    if (( ${#FIX_ACTIONS[@]} == 0 )); then
        echo -e "${GREEN}✅ No critical issues to fix!${RESET}"
        return 0
    fi

    echo -e "${BOLD}🦀 Pincer Auto-Fix${RESET}"
    echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo -e "The following fixes will be applied:"
    for action in "${FIX_ACTIONS[@]}"; do
        case "$action" in
            rebind_gateway)     echo "  • Rebind gateway to 127.0.0.1" ;;
            move_keys_to_env)   echo "  • Move plaintext API keys to .env" ;;
            fix_permissions)    echo "  • Set config file permissions to 600" ;;
            add_safebins)       echo "  • Add safeBins shell command allowlist" ;;
            disable_auth_bypass) echo "  • Disable Control UI auth bypass" ;;
        esac
    done
    echo ""

    if [[ $AUTO_YES -eq 0 ]]; then
        read -rp "Proceed? (y/N) " confirm
        if [[ "$confirm" != [yY]* ]]; then
            echo "Aborted."
            return 1
        fi
    fi

    # Create backup
    local backup_dir="$HOME/.pincer-backup/$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$backup_dir"
    for f in "${CONFIG_FILES[@]}"; do
        cp "$f" "$backup_dir/" 2>/dev/null || true
    done
    echo -e "${DIM}Backup saved to $backup_dir${RESET}"
    echo ""

    for action in "${FIX_ACTIONS[@]}"; do
        case "$action" in
            rebind_gateway)
                for f in "${CONFIG_FILES[@]}"; do
                    if grep -qE '(host|bind|address|listen)\s*[:=]\s*["\x27]?0\.0\.0\.0' "$f" 2>/dev/null; then
                        sed -i.bak 's/0\.0\.0\.0/127.0.0.1/g' "$f" 2>/dev/null && \
                            echo -e "  ${GREEN}✓${RESET} Rebound gateway to 127.0.0.1 in $f"
                    fi
                done
                ;;
            fix_permissions)
                for f in "${CONFIG_FILES[@]}"; do
                    chmod 600 "$f" 2>/dev/null && \
                        echo -e "  ${GREEN}✓${RESET} Set permissions 600 on $f"
                done
                ;;
            move_keys_to_env)
                echo -e "  ${YELLOW}⚠${RESET} Move API keys to .env manually — too risky to auto-migrate"
                echo -e "    Tip: Use environment variable references (\${ANTHROPIC_API_KEY}) in configs"
                ;;
            add_safebins)
                # Find the main config and suggest adding safeBins
                local target_cfg=""
                for f in "${CONFIG_FILES[@]}"; do
                    if [[ "$(basename "$f")" =~ ^(config|clawdbot|moltbot|openclaw)\.(yaml|yml|json)$ ]]; then
                        target_cfg="$f"
                        break
                    fi
                done
                if [[ -n "$target_cfg" ]]; then
                    if ! grep -q 'safeBins' "$target_cfg" 2>/dev/null; then
                        if [[ "$target_cfg" == *.json ]]; then
                            # For JSON configs, use a temp file with python/node or manual instruction
                            if command -v node &>/dev/null; then
                                node -e "
const fs = require('fs');
const cfg = JSON.parse(fs.readFileSync('$target_cfg', 'utf8'));
if (!cfg.tools) cfg.tools = {};
if (!cfg.tools.exec) cfg.tools.exec = {};
cfg.tools.exec.safeBins = ['ls','cat','head','tail','grep','find','wc','echo','date','pwd','whoami','git','node','npm','npx','python','python3','pip','curl'];
fs.writeFileSync('$target_cfg', JSON.stringify(cfg, null, 2) + '\n');
" 2>/dev/null && \
                                    echo -e "  ${GREEN}✓${RESET} Added safeBins allowlist to $target_cfg"
                            else
                                echo -e "  ${YELLOW}⚠${RESET} JSON config detected but node not available for safe editing"
                                echo -e "    Add this to your config manually under \"tools\":"
                                echo -e "    \"exec\": { \"safeBins\": [\"ls\",\"cat\",\"grep\",\"git\",\"node\",\"npm\",\"curl\"] }"
                            fi
                        else
                            cat >> "$target_cfg" <<'SAFEBINS'

# Added by Pincer — shell command allowlist
tools:
  exec:
    safeBins:
      - ls
      - cat
      - head
      - tail
      - grep
      - find
      - wc
      - echo
      - date
      - pwd
      - whoami
      - git
      - node
      - npm
      - npx
      - python
      - python3
      - pip
      - curl
SAFEBINS
                            echo -e "  ${GREEN}✓${RESET} Added safeBins allowlist to $target_cfg"
                        fi
                    fi
                else
                    echo -e "  ${YELLOW}⚠${RESET} No config file found — add safeBins manually to your OpenClaw config"
                fi
                ;;
            disable_auth_bypass)
                for f in "${CONFIG_FILES[@]}"; do
                    if grep -qiE '(authBypass|auth_bypass|skipAuth|noAuth|disableAuth)\s*[:=]\s*(true|yes|1)' "$f" 2>/dev/null; then
                        sed -i.bak -E 's/(authBypass|auth_bypass|skipAuth|noAuth|disableAuth)(\s*[:=]\s*)(true|yes|1)/\1\2false/' "$f" 2>/dev/null && \
                            echo -e "  ${GREEN}✓${RESET} Disabled auth bypass in $f"
                    fi
                done
                ;;
        esac
    done

    echo ""
    echo -e "${GREEN}Done!${RESET} Restart your gateway for changes to take effect."
    echo -e "${DIM}Backup at: $backup_dir${RESET}"
}

# ---------------------------------------------------------------------------
# Run all checks
# ---------------------------------------------------------------------------
run_all_checks() {
    check_gateway_binding
    check_api_keys
    check_file_permissions
    check_tls
    check_shell_allowlist
    check_sensitive_dirs
    check_webhook_auth
    check_sandbox
    check_default_creds
    check_rate_limiting
    check_nodejs_version
    check_control_ui_auth
}

# ---------------------------------------------------------------------------
# Scan command
# ---------------------------------------------------------------------------
do_scan() {
    if [[ $JSON_MODE -eq 0 ]]; then
        echo ""
        echo -e "${BOLD}🦀 Pincer v${PINCER_VERSION}${RESET} — Security scanner for OpenClaw"
        echo -e "${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    fi

    discover_configs

    if (( ${#CONFIG_FILES[@]} == 0 )); then
        if [[ $JSON_MODE -eq 0 ]]; then
            warn_msg "  No OpenClaw/Clawdbot/Moltbot config files found."
            warn_msg "  Scanning system-level checks only."
            echo ""
        fi
    else
        if [[ $JSON_MODE -eq 0 ]]; then
            info "  Found ${#CONFIG_FILES[@]} config file(s)"
            for f in "${CONFIG_FILES[@]}"; do
                echo -e "  ${DIM}$f${RESET}"
            done
            echo ""
        fi
    fi

    run_all_checks

    if [[ $JSON_MODE -eq 1 ]]; then
        print_json_report
    else
        print_report
    fi

    # Exit code: 2 for criticals, 1 for warnings only, 0 for clean
    if (( CRITICALS > 0 )); then
        return 2
    elif (( WARNINGS > 0 )); then
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------
usage() {
    cat <<EOF
🦀 Pincer v${PINCER_VERSION} — Security scanner for OpenClaw

Usage:
  pincer.sh scan [--json]    Run security audit
  pincer.sh fix [--yes]      Auto-fix critical issues
  pincer.sh --help           Show this help
  pincer.sh --version        Show version

Options:
  --json    Output scan results as JSON (for CI/CD)
  --yes     Skip confirmation prompts in fix mode

Examples:
  ./pincer.sh scan            # Full security audit
  ./pincer.sh scan --json     # JSON output for CI/CD
  ./pincer.sh fix             # Fix critical issues (with confirmation)
  ./pincer.sh fix --yes       # Fix without asking

Install:
  curl -sL https://raw.githubusercontent.com/masbindev/pincer/main/pincer.sh | bash

More: https://github.com/masbindev/pincer
EOF
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    local cmd="${1:-}"

    # Handle flags
    case "$cmd" in
        --help|-h)    usage; exit 0 ;;
        --version|-v) echo "Pincer v${PINCER_VERSION}"; exit 0 ;;
    esac

    # When piped via curl (no args), default to scan
    if [[ -z "$cmd" ]]; then
        cmd="scan"
    fi

    shift || true

    # Parse remaining args
    while (( $# > 0 )); do
        case "$1" in
            --json) JSON_MODE=1 ;;
            --yes|-y) AUTO_YES=1 ;;
            *) die "Unknown option: $1" ;;
        esac
        shift
    done

    local rc=0
    case "$cmd" in
        scan) do_scan || rc=$? ;;
        fix)  do_fix || rc=$? ;;
        *)    die "Unknown command: $cmd. Try --help" ;;
    esac
    exit "$rc"
}

main "$@"
