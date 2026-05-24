# 🎯 ReconXploit Cheatsheet

Ultimate Automated Reconnaissance Platform for Bug Bounty Hunters.

## 🚀 Quick Aliases
If you've added the aliases to your `.zshrc`:
- `reconxp` -> Main scanning engine
- `rx-cli` -> Target & Result management CLI

---

## 🔍 Scanning (reconxp)
The main engine for running scans.

| Command | Description |
|---------|-------------|
| `reconxp target.com` | Run a **Full Scan** (Discovery to Screenshots) |
| `reconxp target.com --mode passive` | **Passive Only**: APIs + Cert logs (no active probing) |
| `reconxp target.com --mode quick` | **Quick Scan**: Discovery + Live host validation |
| `reconxp target.com --mode deep` | **Deep Scan**: Full scan + Brute force wordlists |
| `reconxp --mode auto` | **Automation Daemon**: Runs on all targets in `data/targets.txt` |
| `reconxp --status` | Show scheduler status for all targets |
| `reconxp target.com --force` | Force immediate re-scan (ignore schedule) |

---

## 🛠️ Management (rx-cli)
Manage targets and view structured results.

### Target Management
| Command | Description |
|---------|-------------|
| `rx-cli add-target target.com` | Add a new target to the database |
| `rx-cli list-targets` | List all monitored targets |
| `rx-cli remove-target target.com` | Remove a target and its data |

### Viewing Results
| Command | Description |
|---------|-------------|
| `rx-cli show-results target.com` | Show a summary of findings |
| `rx-cli show-results target.com -t subdomains` | List all discovered subdomains |
| `rx-cli show-results target.com -t vulns` | List found vulnerabilities |
| `rx-cli show-results target.com -t ports` | List open ports |
| `rx-cli show-results target.com -t changes` | Show recent changes detected |

---

## 📂 Data Locations
- **Subdomains:** `data/subdomains/[domain].txt`
- **Live Hosts:** `data/live_hosts/[domain].txt`
- **Vulnerabilities:** `data/vulnerabilities/[domain].txt`
- **Screenshots:** `data/screenshots/[domain]/`
- **JS Findings:** `data/js_findings/[domain].txt`

---

## ⚙️ System Commands
| Command | Description |
|---------|-------------|
| `rx-cli health` | Check if DB, Redis, and tools are working |
| `rx-cli init-db` | Initialize/Reset the database schema |

---

## 🌊 Workflow Example
1. **Add target:** `rx-cli add-target example.com`
2. **Start Scan:** `reconxp example.com`
3. **Check Results:** `rx-cli show-results example.com`
4. **Monitor Everything:** `reconxp --mode auto`
