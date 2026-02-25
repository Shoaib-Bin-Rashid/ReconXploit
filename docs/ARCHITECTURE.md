# 🔒 ReconXploit - Technical Architecture

## Security Professional's Deep Dive

---

# 📋 RECONNAISSANCE PHASES OVERVIEW

```
INPUT: target.com
│
├─ Phase 1: Asset Discovery
├─ Phase 2: Asset Validation  
├─ Phase 3: Service Enumeration
├─ Phase 4: Vulnerability Assessment
├─ Phase 5: Intelligence Gathering
├─ Phase 6: Change Detection
└─ Phase 7: Risk Correlation & Reporting
```

---

# 🎯 PHASE 1: ASSET DISCOVERY

**Objective:** Enumerate complete attack surface - find ALL subdomains, IPs, and related infrastructure.

## 1.1 Passive Subdomain Enumeration

**Tools Used:**
- `subfinder` (multi-source aggregator)
- `assetfinder` (focused on specific sources)
- `amass` (passive mode)
- `findomain` (fast passive scanning)

**Data Sources:**
- Certificate Transparency Logs (crt.sh, Censys)
- DNS aggregators (SecurityTrails, VirusTotal)
- Search engines (Google, Bing dorking)
- Web archives

**Output:**
```
api.target.com
admin.target.com
staging.target.com
dev.target.com
mail.target.com
...
```

**Command Flow:**
```bash
subfinder -d target.com -all -o subfinder.txt
assetfinder --subs-only target.com > assetfinder.txt
amass enum -passive -d target.com -o amass.txt
findomain -t target.com -u findomain.txt
```

**Storage:** PostgreSQL table `subdomains`
```sql
id | subdomain | source | discovered_at | status
```

---

## 1.2 Active Subdomain Enumeration

**Tools Used:**
- `amass` (active mode with DNS brute-forcing)
- `puredns` (mass DNS resolver)
- `shuffledns` (DNS bruteforcer)

**Techniques:**
- DNS zone transfers (AXFR)
- Reverse DNS lookups
- Wordlist-based brute-forcing
- Permutation generation (dev-, stage-, prod- prefixes)

**Command Flow:**
```bash
amass enum -active -d target.com -brute -w wordlist.txt
puredns bruteforce wordlist.txt target.com -r resolvers.txt
```

**Permutation Engine:**
```
target.com → dev.target.com, dev-api.target.com, api-dev.target.com
admin.target.com → admin1.target.com, admin-panel.target.com
```

---

## 1.3 ASN & IP Enumeration

**Tools Used:**
- `amass` (ASN discovery)
- `whois`
- `bgpview` (API)

**Objective:** Find all IP ranges owned by target organization.

**Process:**
1. Query WHOIS for organization name
2. Find ASN (Autonomous System Number)
3. Enumerate all CIDR blocks in ASN
4. Reverse DNS on entire ranges

**Command Flow:**
```bash
amass intel -org "Target Corp" -whois
whois -h whois.radb.net -- '-i origin AS15169'
```

**Output:** All IP ranges → expand to individual IPs → reverse DNS → more subdomains

---

## 1.4 Cloud Asset Enumeration

**Tools Used:**
- `cloud_enum` (AWS, Azure, GCP)
- Custom scripts for permutations

**Targets:**
- S3 buckets: `target-prod.s3.amazonaws.com`
- Azure blobs: `target.blob.core.windows.net`
- GCP buckets: `target-backups.storage.googleapis.com`

**Permutations:**
```
target, target-prod, target-dev, target-backup, target-data,
targetcom, target-assets, target-files, target-media
```

**Command Flow:**
```bash
cloud_enum -k target.com -k target
```

---

## 1.5 Domain Relationship Mapping

**Tools Used:**
- `amass` (graph visualization)
- Custom graph database (Neo4j optional)

**Maps:**
- Parent → Child domains
- IP → Domain relationships
- ASN → IP → Domain chains

---

# 🔍 PHASE 2: ASSET VALIDATION

**Objective:** Determine which discovered assets are actually live and accessible.

## 2.1 HTTP/HTTPS Probing

**Tools Used:**
- `httpx` (fast HTTP prober)
- `httprobe` (alternative)

**Checks:**
- HTTP/HTTPS availability
- Status codes (200, 301, 302, 403, 401, 500)
- Response time
- Content length
- Page title
- Server headers
- TLS/SSL certificate info
- Technology fingerprints

**Command Flow:**
```bash
cat subdomains.txt | httpx -status-code -title -tech-detect \
  -server -content-length -follow-redirects -json -o httpx.json
```

**Output JSON:**
```json
{
  "url": "https://admin.target.com",
  "status-code": 200,
  "title": "Admin Login",
  "content-length": 4521,
  "server": "nginx/1.18.0",
  "tech": ["PHP", "MySQL"],
  "tls": {
    "cipher": "TLS_AES_128_GCM_SHA256",
    "version": "TLS 1.3"
  }
}
```

**Storage:** PostgreSQL table `live_hosts`
```sql
id | url | status_code | title | server | content_length | 
   tech_stack | screenshot_path | last_checked | fingerprint_hash
```

---

## 2.2 Screenshot Capture

**Tools Used:**
- `gowitness` (headless browser screenshots)
- `eyewitness` (alternative with reporting)

**Purpose:**
- Visual identification of login panels
- Detection of default pages
- Identification of web technologies
- Quick triage of interesting targets

**Command Flow:**
```bash
gowitness file -f live_urls.txt --screenshot-path ./screenshots/
```

**Storage:** Screenshots saved + path stored in DB

---

## 2.3 WAF & CDN Detection

**Tools Used:**
- `wafw00f` (WAF detection)
- `httpx` (CDN headers)

**Identifies:**
- Cloudflare, Akamai, AWS CloudFront
- Application firewalls (ModSecurity, F5, Imperva)
- Rate limiting headers

**Why it matters:** Bypass strategies differ per WAF/CDN

---

# 🔌 PHASE 3: SERVICE ENUMERATION

**Objective:** Identify all running services, open ports, and versions.

## 3.1 Port Scanning

**Tools Used:**
- `nmap` (detailed scanning)
- `masscan` (fast scanning for large scope)
- `naabu` (fast port scanner)

**Scan Types:**

**Fast Scan (common ports):**
```bash
naabu -l hosts.txt -top-ports 1000 -o ports.txt
```

**Full Scan (all ports):**
```bash
nmap -p- -T4 -iL hosts.txt -oX nmap_full.xml
```

**Service Detection:**
```bash
nmap -sV -sC -p <ports> -iL hosts.txt -oX nmap_services.xml
```

**Flags Explained:**
- `-sV`: Version detection
- `-sC`: Default scripts (safe checks)
- `-p-`: All 65535 ports
- `-T4`: Aggressive timing

**Common Interesting Ports:**
```
22   - SSH (check for weak auth)
21   - FTP (anonymous login?)
3306 - MySQL (exposed DB?)
5432 - PostgreSQL
6379 - Redis (unauth access?)
27017 - MongoDB (no auth?)
9200 - Elasticsearch (open indices?)
8080, 8443, 8888 - Alt HTTP/HTTPS
3000, 5000, 8000 - Dev servers
```

**Storage:** PostgreSQL table `ports`
```sql
id | host | port | protocol | service | version | state | banner
```

---

## 3.2 Service Fingerprinting

**Tools Used:**
- `nmap` NSE scripts
- `whatweb` (web tech)
- `wappalyzer` (via API/CLI)

**Collects:**
- Server software + version
- Programming language
- Frameworks (Laravel, Django, Express)
- CMS (WordPress, Joomla, Drupal)
- JavaScript libraries
- Analytics (Google Analytics, GTM)
- CDN/Hosting provider

**Command Flow:**
```bash
whatweb -i urls.txt --log-json=whatweb.json
```

---

# 🧨 PHASE 4: VULNERABILITY ASSESSMENT

**Objective:** Identify security weaknesses in discovered assets.

## 4.1 Template-Based Scanning

**Tools Used:**
- `nuclei` (primary vulnerability scanner)

**Template Categories:**
- CVEs (known vulnerabilities)
- Exposed panels (admin, login, debug)
- Misconfigurations (CORS, SSRF, XXE)
- Default credentials
- Information disclosure
- Security headers missing

**Command Flow:**
```bash
nuclei -l live_hosts.txt -t ~/nuclei-templates/ \
  -severity critical,high,medium \
  -json -o nuclei_results.json
```

**Severity Levels:**
- **Critical:** RCE, SQL injection, auth bypass
- **High:** XSS, SSRF, sensitive data exposure
- **Medium:** Missing headers, info disclosure
- **Low:** Version disclosure
- **Info:** Technology fingerprints

**Storage:** PostgreSQL table `vulnerabilities`
```sql
id | host | vulnerability_name | severity | cvss_score | 
   template_id | matched_at | status | poc_url
```

---

## 4.2 Subdomain Takeover Detection

**Tools Used:**
- `subjack` (subdomain takeover checker)
- `nuclei` (takeover templates)

**Checks for:**
- Dangling CNAME records
- Unclaimed cloud resources (GitHub Pages, AWS, Azure)
- Expired S3 buckets
- Heroku apps

**Command Flow:**
```bash
subjack -w subdomains.txt -t 50 -timeout 30 -o takeovers.txt -v
```

---

## 4.3 Technology-Specific Scanning

**WordPress:**
- `wpscan` (plugin/theme vulns)

**Drupal:**
- `droopescan`

**Joomla:**
- `joomscan`

**Command Flow:**
```bash
wpscan --url https://blog.target.com --enumerate vp,vt,u --api-token XXX
```

---

# 🧠 PHASE 5: INTELLIGENCE GATHERING

**Objective:** Extract deeper intelligence from assets.

## 5.1 JavaScript Analysis

**Tools Used:**
- `subjs` (extract JS files)
- `getJS` (alternative)
- `LinkFinder` (endpoint extraction)
- `SecretFinder` (secrets in JS)
- Custom regex engine

**Process:**
1. Extract all JS file URLs
2. Download JS files
3. Beautify minified code
4. Analyze for:
   - API endpoints
   - Internal URLs
   - AWS keys (`AKIA[A-Z0-9]{16}`)
   - API tokens
   - GraphQL endpoints
   - WebSocket URLs
   - Firebase configs
   - Hidden parameters

**Command Flow:**
```bash
# Extract JS URLs
cat urls.txt | subjs > js_files.txt

# Find endpoints
python3 linkfinder.py -i https://target.com/app.js -o endpoints.txt

# Find secrets
python3 secretfinder.py -i https://target.com/app.js -o secrets.txt
```

**Regex Patterns:**
```regex
AWS Key: (AKIA[0-9A-Z]{16})
API Key: [aA][pP][iI]_?[kK][eE][yY].*['|"][0-9a-zA-Z]{32,45}
JWT: eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*
```

**Storage:** PostgreSQL table `js_intelligence`
```sql
id | source_url | js_file_url | endpoint | secret_type | 
   secret_value | risk_level | discovered_at
```

---

## 5.2 Parameter Discovery

**Tools Used:**
- `arjun` (parameter fuzzing)
- `paramspider` (archive mining)
- `x8` (hidden parameter discovery)

**Why it matters:** More parameters = more injection points

**Command Flow:**
```bash
# Find parameters in archives
paramspider -d target.com -o params.txt

# Fuzz for hidden parameters
arjun -u https://api.target.com/endpoint -o params.json
```

**Example Output:**
```
https://api.target.com/users?id=1&debug=true&admin=false
```

Hidden param `admin` or `debug` = potential vuln

---

## 5.3 Historical Intelligence (Wayback Machine)

**Tools Used:**
- `waybackurls` (archive URL extraction)
- `gau` (get all URLs)

**Extracts:**
- Old endpoints (possibly forgotten)
- Deprecated APIs
- Removed admin panels
- Old parameters
- Historical JS files

**Command Flow:**
```bash
waybackurls target.com > wayback_urls.txt
gau target.com > all_urls.txt
```

**Analysis:**
- Compare old URLs vs current
- Look for removed endpoints (still work?)
- Find old API versions (`/api/v1/` vs `/api/v2/`)

---

## 5.4 Directory & File Enumeration

**Tools Used:**
- `ffuf` (fast fuzzer)
- `dirsearch` (directory scanner)
- `feroxbuster` (recursive scanner)

**Wordlists:**
- `SecLists` (common paths)
- Custom wordlists

**Command Flow:**
```bash
ffuf -u https://target.com/FUZZ -w wordlist.txt \
  -mc 200,301,302,403 -o ffuf.json
```

**Common Findings:**
```
/admin
/api/docs
/swagger
/.git
/.env
/backup.sql
/phpinfo.php
```

---

## 5.5 DNS Intelligence

**Tools Used:**
- `dnsx` (DNS toolkit)
- `fierce` (DNS enumeration)

**Checks:**
- DNS zone transfer (AXFR)
- DNS records (A, AAAA, CNAME, MX, TXT, NS)
- SPF/DMARC misconfigs
- CAA records

**Command Flow:**
```bash
dnsx -l subdomains.txt -resp -a -aaaa -cname -mx -txt -json
```

---

# 🔄 PHASE 6: CHANGE DETECTION ENGINE

**Objective:** Track changes over time - THE KILLER FEATURE.

## 6.1 Baseline Creation

**First Scan:**
- Store complete state in DB
- Create fingerprints (hashes) for:
  - Subdomain list
  - Live host responses
  - Open ports
  - Service versions
  - JS file contents
  - Technology stack

**Storage Schema:**
```sql
-- Snapshots table
CREATE TABLE snapshots (
  id SERIAL PRIMARY KEY,
  scan_date TIMESTAMP,
  target VARCHAR(255),
  snapshot_hash VARCHAR(64)
);

-- Asset history
CREATE TABLE asset_history (
  id SERIAL PRIMARY KEY,
  snapshot_id INTEGER,
  asset_type VARCHAR(50), -- subdomain, port, vuln, etc.
  asset_data JSONB,
  fingerprint VARCHAR(64)
);
```

---

## 6.2 Differential Analysis

**Each Subsequent Scan:**

Compare current state vs last snapshot:

**Subdomain Changes:**
```sql
-- New subdomains
SELECT current.subdomain 
FROM current_scan current
LEFT JOIN last_scan last ON current.subdomain = last.subdomain
WHERE last.subdomain IS NULL;

-- Removed subdomains
SELECT last.subdomain 
FROM last_scan last
LEFT JOIN current_scan current ON last.subdomain = current.subdomain
WHERE current.subdomain IS NULL;
```

**Port Changes:**
```sql
-- New open ports
-- Closed ports
-- Service version changes
```

**Content Changes:**
```bash
# Compare page fingerprints
current_hash=$(curl -s https://target.com | sha256sum)
if [ "$current_hash" != "$previous_hash" ]; then
  echo "Page content changed!"
fi
```

---

## 6.3 Change Categories

**High Priority Changes:**
- ✅ New subdomain discovered
- ✅ New open port (especially 22, 3306, 5432, 6379)
- ✅ Service version downgrade (rollback = possible vuln)
- ✅ New critical/high vulnerability
- ✅ New JS secret found
- ✅ Subdomain takeover now possible
- ✅ Public S3 bucket exposed

**Medium Priority:**
- ⚠️ Technology stack change
- ⚠️ SSL certificate change
- ⚠️ New endpoints discovered
- ⚠️ WAF/CDN change

**Low Priority:**
- ℹ️ Page title change
- ℹ️ Content length change
- ℹ️ Minor version updates

---

## 6.4 Anomaly Detection

**Statistical Analysis:**
- Sudden spike in subdomains → acquisitions/launches
- Port closures → security hardening
- Multiple vulnerabilities → recent deployment

---

# 📊 PHASE 7: RISK CORRELATION & REPORTING

**Objective:** Prioritize findings and generate actionable intelligence.

## 7.1 Risk Scoring Engine

**Algorithm:**

```python
risk_score = 0

# Vulnerability severity
if severity == "critical": risk_score += 40
elif severity == "high": risk_score += 25
elif severity == "medium": risk_score += 10

# Asset exposure
if publicly_accessible: risk_score += 15
if no_waf: risk_score += 10

# Technology factors
if outdated_version: risk_score += 15
if eol_software: risk_score += 20

# Sensitive services
if port in [22, 3306, 5432, 6379, 27017]: risk_score += 20

# Intelligence findings
if api_key_found: risk_score += 30
if admin_panel: risk_score += 20

# Change factors
if new_asset: risk_score += 10
if recent_change: risk_score += 5

# Final score: 0-100
```

**Output:**
```
admin-panel.target.com - Risk Score: 85 (CRITICAL)
- Exposed admin login (no WAF)
- Outdated WordPress 5.2
- Known RCE vulnerability
- No rate limiting
```

---

## 7.2 Attack Surface Mapping

**Graph Visualization:**
```
target.com
├── api.target.com (Risk: 75)
│   ├── Port 443 (nginx 1.14 - vulnerable)
│   ├── GraphQL endpoint exposed
│   └── AWS keys in JS
├── admin.target.com (Risk: 90)
│   ├── Port 80 (redirect)
│   ├── Port 443 (admin panel)
│   └── Default credentials possible
└── staging.target.com (Risk: 60)
    └── .git folder exposed
```

---

## 7.3 Alert Generation

**Alert Rules:**

```yaml
alert_rules:
  - condition: new_subdomain AND risk_score > 70
    channel: telegram, discord
    priority: high
  
  - condition: critical_vulnerability
    channel: telegram, email
    priority: critical
  
  - condition: secret_in_js
    channel: telegram
    priority: high
  
  - condition: subdomain_takeover
    channel: all
    priority: critical
```

**Alert Format:**
```
🚨 CRITICAL ALERT

New Asset Detected:
URL: https://api-v3.target.com
Risk Score: 85/100

Findings:
❌ Exposed API documentation (/docs)
❌ No authentication required
❌ CORS misconfiguration (allow all)
❌ Rate limiting disabled
✅ SQL injection in /users endpoint

Recommended Action:
Test /users endpoint immediately

Discovered: 2026-02-21 09:15 UTC
```

---

## 7.4 Reporting Formats

**Dashboard:** Real-time web interface

**Export Formats:**
- JSON (for automation)
- CSV (for spreadsheets)
- PDF (for clients)
- HTML (shareable reports)
- Markdown (for notes)

**Report Sections:**
1. Executive Summary
2. Asset Inventory
3. Vulnerability Summary
4. Change Timeline
5. Risk Heatmap
6. Remediation Recommendations

---

# 🔧 TECHNICAL ARCHITECTURE

## Database Schema (PostgreSQL)

```sql
-- Core tables
targets (id, domain, status, created_at)
scans (id, target_id, start_time, end_time, status)
subdomains (id, scan_id, subdomain, source, discovered_at)
live_hosts (id, scan_id, url, status, fingerprint)
ports (id, host_id, port, service, version)
vulnerabilities (id, host_id, vuln_name, severity, cvss)
js_intelligence (id, host_id, endpoint, secret_type)
changes (id, scan_id, change_type, old_value, new_value)
risk_scores (id, asset_id, score, factors)
alerts (id, target_id, alert_type, sent_at, channel)
```

---

## Automation Workflow

```python
# Celery task scheduler
@celery.task
def run_recon_pipeline(target_id):
    # Phase 1: Discovery
    subdomains = discover_subdomains(target)
    
    # Phase 2: Validation
    live_hosts = validate_hosts(subdomains)
    
    # Phase 3: Enumeration
    ports = scan_ports(live_hosts)
    
    # Phase 4: Vulnerability scanning
    vulns = scan_vulnerabilities(live_hosts)
    
    # Phase 5: Intelligence
    js_data = analyze_javascript(live_hosts)
    params = discover_parameters(live_hosts)
    
    # Phase 6: Change detection
    changes = detect_changes(current_scan, previous_scan)
    
    # Phase 7: Risk scoring
    risks = calculate_risk_scores()
    
    # Generate alerts
    if changes or critical_vulns:
        send_alerts()
```

---

## Scan Scheduling

```python
# Cron-based scheduling
schedules = {
    'daily_full_scan': '0 2 * * *',      # 2 AM daily
    'hourly_quick_scan': '0 * * * *',    # Every hour
    'weekly_deep_scan': '0 3 * * 0',     # Sunday 3 AM
}
```

---

# 🎯 TOOL SUMMARY BY PHASE

| Phase | Tools | Purpose |
|-------|-------|---------|
| **Discovery** | subfinder, amass, assetfinder, findomain | Find subdomains |
| **Validation** | httpx, gowitness | Check if alive + screenshot |
| **Enumeration** | nmap, masscan, naabu | Port/service scanning |
| **Vulnerability** | nuclei, wpscan | Find security issues |
| **Intelligence** | subjs, linkfinder, arjun, waybackurls | Extract data |
| **Change Detection** | Custom diff engine | Track changes |
| **Reporting** | Custom dashboard | Visualize results |

---

# 💾 DATA FLOW

```
Input: target.com
  ↓
[Discovery Phase] → subdomains.txt (500 subdomains)
  ↓
[Validation Phase] → live_hosts.txt (120 alive)
  ↓
[Enumeration Phase] → ports.json (2,400 open ports)
  ↓
[Vulnerability Phase] → vulnerabilities.json (45 findings)
  ↓
[Intelligence Phase] → endpoints.txt, secrets.txt
  ↓
[Change Detection] → changes.json (15 changes)
  ↓
[Risk Scoring] → risk_report.json
  ↓
[Output] → Dashboard + Telegram Alert
```

---

# ⚡ EXECUTION TIMELINE

**Full Recon Scan (medium target):**
- Discovery: 15-30 min
- Validation: 5-10 min
- Enumeration: 20-40 min
- Vulnerability: 30-60 min
- Intelligence: 15-30 min
- Analysis: 5-10 min

**Total: ~2-3 hours** (automated, runs overnight)

---

**This is the complete technical methodology. Each phase builds on the previous, creating comprehensive attack surface intelligence.** 🎯
