# 🦀 Pincer

**Security scanner for OpenClaw — one script, zero dependencies.**

Pincer audits your [OpenClaw](https://github.com/nichochar/open-claw)/Clawdbot/Moltbot installation for security misconfigurations and common vulnerabilities. Pure bash, runs anywhere, fixes what it finds.

## Why?

- [Forbes (Jan 2026)](https://www.forbes.com/sites/daveywinder/2026/01/30/ai-chatbot-hacking-alert-as-hundreds-of-servers-found-exposed/): *"Hundreds of Moltbot servers found exposed on the open internet"*
- [Cisco AI Defense](https://github.com/cisco-ai-defense/skill-scanner): Documented prompt injection and malicious skill vectors
- [CVE-2026-21636](https://nvd.nist.gov/vuln/detail/CVE-2026-21636): Node.js permission model bypass affects OpenClaw setups

**The problem:** Most OpenClaw installations run with default settings — gateway on 0.0.0.0, no auth, no command allowlist, plaintext API keys. Pincer finds and fixes these issues in seconds.

## Install

**Quick scan (no install):**
```bash
curl -sL https://raw.githubusercontent.com/masbindev/pincer/main/pincer.sh | bash
```

**Install locally (recommended — enables `fix` command):**
```bash
curl -sL https://raw.githubusercontent.com/masbindev/pincer/main/pincer.sh -o pincer.sh
chmod +x pincer.sh
./pincer.sh scan
```

**Or clone the repo:**
```bash
git clone https://github.com/masbindev/pincer.git
cd pincer && ./pincer.sh scan
```

## Usage

```bash
# Full security audit
./pincer.sh scan

# JSON output (for CI/CD)
./pincer.sh scan --json

# Auto-fix critical issues
./pincer.sh fix

# Fix without confirmation prompt
./pincer.sh fix --yes
```

### Sample Output

```
🦀 Pincer Security Report
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Score: 65/100 (D)

🔴 CRITICAL
  ├─ Gateway exposed on 0.0.0.0 (should be 127.0.0.1)
  ├─ No shell command allowlist (safeBins not configured)
  └─ Node.js 22.12.0 may be vulnerable to CVE-2026-21636

🟡 WARNING
  ├─ HTTPS/TLS not configured
  ├─ Sensitive directories accessible (~/.ssh ~/.gnupg)
  └─ No rate limiting configured

🟢 PASSED
  ├─ API keys not found in plaintext configs
  ├─ Config file permissions OK
  ├─ Gateway auth token set and not using defaults
  └─ Control UI auth bypass disabled

💡 RECOMMENDATIONS
  ├─ Run: cisco-ai-defense/skill-scanner to audit your skills
  └─ See: https://github.com/masbindev/pincer for fix guides

Run ./pincer.sh fix to auto-fix critical issues.
```

## Security Checks (12)

| # | Check | Severity | What it detects |
|---|-------|----------|-----------------|
| 1 | **Gateway Binding** | CRITICAL | Gateway listening on 0.0.0.0 instead of 127.0.0.1 |
| 2 | **API Keys Exposure** | CRITICAL | Plaintext API keys/tokens in config files (not .env) |
| 3 | **File Permissions** | CRITICAL | World-readable config files (should be 600) |
| 4 | **HTTPS/TLS** | WARNING | No TLS/HTTPS configuration detected |
| 5 | **Shell Command Allowlist** | CRITICAL | Missing `tools.exec.safeBins` — agent can run any command |
| 6 | **Sensitive Directories** | WARNING | Agent can access ~/.ssh, ~/.gnupg, ~/.aws, /etc/shadow |
| 7 | **Webhook Auth** | WARNING | Webhook endpoints without authentication |
| 8 | **Sandbox Isolation** | WARNING | Not running in Docker/sandbox |
| 9 | **Default/Weak Credentials** | CRITICAL | Default tokens, `undefined` token bug, missing gateway auth |
| 10 | **Rate Limiting** | WARNING | No rate limiting configured |
| 11 | **Node.js Version** | CRITICAL | CVE-2026-21636 permission model bypass |
| 12 | **Control UI Auth** | CRITICAL | Auth bypass flag enabled |

## Fix Command

`pincer.sh fix` auto-remediates critical issues:

- Rebinds gateway to 127.0.0.1
- Sets config file permissions to 600
- Adds `safeBins` allowlist with sensible defaults
- Disables Control UI auth bypass
- Creates timestamped backup before any changes

## How Pincer Differs

| | **Pincer** | **ClawShield** (kappa9999) | **Cisco Skill Scanner** |
|---|---|---|---|
| **Focus** | Infra & config hardening | Audit + exposure + lockfile | Skill content scanning |
| **Language** | Pure bash | Go + Python | Python |
| **Dependencies** | Zero (coreutils only) | Go runtime, Python | Python, pip |
| **Install** | One curl command | Build from source | pip install |
| **Auto-fix** | ✅ Yes | Partial | No |
| **Complements** | — | Overlaps | ✅ Use together! |

**Recommended combo:** Run Pincer for infrastructure hardening, then [cisco-ai-defense/skill-scanner](https://github.com/cisco-ai-defense/skill-scanner) to audit skill contents for prompt injection.

## Requirements

- Bash 4+
- Standard coreutils (grep, awk, stat, sed, ss)
- Works on any Linux distro, macOS with GNU coreutils

## Contributing

PRs welcome! Please:
1. Keep it pure bash — no external dependencies
2. Run `shellcheck pincer.sh` before submitting
3. Add tests for new checks

## License

MIT — see [LICENSE](LICENSE)
