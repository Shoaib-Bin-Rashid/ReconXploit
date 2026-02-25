# ReconXploit

> Ultimate Automated Reconnaissance Platform for Bug Bounty Hunters

🚀 **Automate 90% of your recon workflow**

ReconXploit is a comprehensive reconnaissance automation platform that discovers attack surfaces, tracks changes, and prioritizes vulnerabilities automatically.

## 🔥 Features

- **Multi-Phase Reconnaissance**: Subdomain discovery → Live validation → Port scanning → Vulnerability detection
- **Change Detection**: Track what's new, what changed, what disappeared
- **Risk Scoring**: Intelligent prioritization of findings
- **JavaScript Intelligence**: Extract hidden endpoints, API keys, secrets
- **Screenshot Gallery**: Visual reconnaissance of all live assets
- **Automated Alerts**: Telegram notifications for critical findings
- **Web Dashboard**: Clean UI for managing targets and viewing results

## 🎯 What It Does

ReconXploit runs 7 reconnaissance phases automatically:

1. **Asset Discovery** - Find all subdomains, IPs, cloud resources
2. **Asset Validation** - Identify live hosts, capture screenshots
3. **Service Enumeration** - Scan ports, detect services and versions
4. **Vulnerability Assessment** - Run Nuclei templates, detect misconfigs
5. **Intelligence Gathering** - Analyze JS, find secrets, discover parameters
6. **Change Detection** - Compare with previous scans, identify changes
7. **Risk Correlation** - Calculate risk scores, generate alerts

## 🛠️ Tech Stack

**Backend:**
- Python 3.10+
- FastAPI (REST API)
- Celery + Redis (Task Queue)
- PostgreSQL (Database)

**Frontend:**
- React 18
- Tailwind CSS
- Axios

**Recon Tools:**
- subfinder, amass, assetfinder, findomain (Subdomain discovery)
- httpx, gowitness (Validation + Screenshots)
- naabu, nmap (Port scanning)
- nuclei (Vulnerability scanning)
- LinkFinder, SecretFinder (JS analysis)

## 📁 Project Structure

```
reconxploit/
├── backend/
│   ├── api/              # FastAPI routes
│   ├── core/             # Core business logic
│   ├── models/           # Database models
│   ├── modules/          # Recon modules (subdomain, scan, etc.)
│   ├── tasks/            # Celery tasks
│   └── utils/            # Helper utilities
├── frontend/
│   ├── public/
│   └── src/
│       ├── components/   # React components
│       ├── pages/        # Page components
│       └── services/     # API services
├── tools/                # External tool integrations
├── scripts/              # Setup and utility scripts
├── config/               # Configuration files
├── data/
│   ├── screenshots/      # Captured screenshots
│   ├── wordlists/        # Subdomain wordlists
│   └── outputs/          # Scan results
└── docs/                 # Documentation
    └── ARCHITECTURE.md   # Technical architecture
```

## 🚀 Quick Start

### Prerequisites

- Python 3.10+
- PostgreSQL 13+
- Redis 6+
- Node.js 16+ (for frontend)
- Go 1.19+ (for installing tools)

### Installation

```bash
# Clone repository
git clone https://github.com/yourusername/reconxploit.git
cd reconxploit

# Setup backend
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Install recon tools
./scripts/install_tools.sh

# Setup database
createdb reconxploit
python manage.py migrate

# Setup frontend
cd ../frontend
npm install

# Configure environment
cp .env.example .env
# Edit .env with your settings
```

### Running

```bash
# Terminal 1: Start Redis
redis-server

# Terminal 2: Start PostgreSQL
# (or use your system's PostgreSQL service)

# Terminal 3: Start Celery worker
cd backend
celery -A app.celery worker --loglevel=info

# Terminal 4: Start FastAPI backend
uvicorn app.main:app --reload

# Terminal 5: Start React frontend
cd frontend
npm start
```

Access dashboard at: `http://localhost:3000`

## 📖 Usage

### CLI

```bash
# Add a target
python cli.py add-target example.com

# Run full scan
python cli.py scan example.com

# List all targets
python cli.py list-targets

# View scan results
python cli.py show-results example.com
```

### Web Dashboard

1. Navigate to `http://localhost:3000`
2. Click "Add Target" and enter domain
3. Click "Run Scan" to start reconnaissance
4. View results in real-time
5. Get notified on Telegram for critical findings

## 🔧 Configuration

Edit `config/settings.yaml`:

```yaml
# Database
database:
  host: localhost
  port: 5432
  name: reconxploit
  user: postgres
  password: yourpassword

# Redis
redis:
  host: localhost
  port: 6379

# Telegram
telegram:
  enabled: true
  bot_token: "YOUR_BOT_TOKEN"
  chat_id: "YOUR_CHAT_ID"

# Scan settings
scanning:
  max_concurrent_scans: 3
  timeout: 7200
  retry_attempts: 3
```

## 📊 Dashboard Features

- **Asset Inventory**: View all discovered subdomains, IPs, services
- **Vulnerability Dashboard**: See all findings sorted by severity
- **Change Timeline**: Track what's new or changed
- **Screenshot Gallery**: Visual overview of all live hosts
- **Risk Heatmap**: Prioritize high-risk targets
- **Export Reports**: Generate PDF/HTML/JSON reports

## 🔔 Alerts

Configure Telegram alerts for:
- New subdomains discovered
- Critical vulnerabilities found
- Exposed admin panels
- Secrets in JavaScript
- High-risk changes detected
- Subdomain takeover opportunities

## 🛣️ Roadmap

**MVP (Current Phase):**
- [x] Project structure
- [ ] Database schema
- [ ] Core recon modules
- [ ] Change detection
- [ ] Basic dashboard
- [ ] Telegram alerts

**Future:**
- Multi-user support
- Team collaboration
- Bug bounty platform integration
- AI-powered anomaly detection
- Cloud deployment (Docker/K8s)
- Mobile app

## 🤝 Contributing

Contributions welcome! Please read CONTRIBUTING.md first.

## ⚠️ Legal Disclaimer

ReconXploit is designed for authorized security testing only. Users are responsible for ensuring they have permission to scan targets. The authors are not responsible for misuse.

## 📄 License

MIT License - see LICENSE file for details.

## 🙏 Acknowledgments

Built on top of amazing open-source security tools:
- ProjectDiscovery (subfinder, httpx, nuclei, naabu)
- OWASP (Amass)
- Tom Hudson (tomnomnom) - various Go tools
- All contributors to the security research community

---

**Built with 🔥 for bug bounty hunters**
