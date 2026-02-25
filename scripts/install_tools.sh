#!/bin/bash

# ReconXploit - Security Tools Installation Script
# This script installs all required reconnaissance tools

set -e

echo "🚀 ReconXploit Tools Installation"
echo "=================================="

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo -e "${RED}❌ Go is not installed. Please install Go 1.19+ first.${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Go found: $(go version)${NC}"

# Create tools directory
TOOLS_DIR="$HOME/reconxploit-tools"
mkdir -p "$TOOLS_DIR"

echo ""
echo "📦 Installing reconnaissance tools to: $TOOLS_DIR"
echo ""

# Function to install Go tool
install_go_tool() {
    local tool_name=$1
    local tool_path=$2
    
    echo -e "${YELLOW}Installing $tool_name...${NC}"
    
    if command -v "$tool_name" &> /dev/null; then
        echo -e "${GREEN}✓ $tool_name already installed${NC}"
    else
        go install "$tool_path@latest"
        echo -e "${GREEN}✓ $tool_name installed${NC}"
    fi
}

# Install subdomain discovery tools
echo "🔍 Subdomain Discovery Tools"
install_go_tool "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
install_go_tool "assetfinder" "github.com/tomnomnom/assetfinder"
install_go_tool "amass" "github.com/owasp-amass/amass/v4/...@master"
install_go_tool "findomain" "github.com/Findomain/Findomain"
install_go_tool "shuffledns" "github.com/projectdiscovery/shuffledns/cmd/shuffledns"
install_go_tool "puredns" "github.com/d3mondev/puredns/v2"

echo ""
echo "🌐 HTTP Probing & Validation"
install_go_tool "httpx" "github.com/projectdiscovery/httpx/cmd/httpx"
install_go_tool "httprobe" "github.com/tomnomnom/httprobe"
install_go_tool "gowitness" "github.com/sensepost/gowitness"

echo ""
echo "🔌 Port Scanning"
install_go_tool "naabu" "github.com/projectdiscovery/naabu/v2/cmd/naabu"

# Check for nmap
if command -v nmap &> /dev/null; then
    echo -e "${GREEN}✓ nmap already installed${NC}"
else
    echo -e "${YELLOW}⚠ nmap not found. Please install manually:${NC}"
    echo "  - macOS: brew install nmap"
    echo "  - Ubuntu/Debian: sudo apt-get install nmap"
    echo "  - CentOS/RHEL: sudo yum install nmap"
fi

echo ""
echo "🧨 Vulnerability Scanning"
install_go_tool "nuclei" "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"

# Update nuclei templates
if command -v nuclei &> /dev/null; then
    echo -e "${YELLOW}Updating nuclei templates...${NC}"
    nuclei -update-templates
    echo -e "${GREEN}✓ Nuclei templates updated${NC}"
fi

echo ""
echo "🧠 Intelligence Gathering"
install_go_tool "waybackurls" "github.com/tomnomnom/waybackurls"
install_go_tool "gau" "github.com/lc/gau/v2/cmd/gau"
install_go_tool "unfurl" "github.com/tomnomnom/unfurl"
install_go_tool "dnsx" "github.com/projectdiscovery/dnsx/cmd/dnsx"

echo ""
echo "🔧 Utility Tools"
install_go_tool "anew" "github.com/tomnomnom/anew"
install_go_tool "qsreplace" "github.com/tomnomnom/qsreplace"

echo ""
echo "🐍 Installing Python-based tools"

PYTHON_TOOLS_DIR="$TOOLS_DIR/python-tools"
mkdir -p "$PYTHON_TOOLS_DIR"
cd "$PYTHON_TOOLS_DIR"

# LinkFinder
if [ ! -d "LinkFinder" ]; then
    echo -e "${YELLOW}Installing LinkFinder...${NC}"
    git clone https://github.com/GerbenJavado/LinkFinder.git
    cd LinkFinder
    pip install -r requirements.txt
    cd ..
    echo -e "${GREEN}✓ LinkFinder installed${NC}"
else
    echo -e "${GREEN}✓ LinkFinder already installed${NC}"
fi

# SecretFinder
if [ ! -d "SecretFinder" ]; then
    echo -e "${YELLOW}Installing SecretFinder...${NC}"
    git clone https://github.com/m4ll0k/SecretFinder.git
    cd SecretFinder
    pip install -r requirements.txt
    cd ..
    echo -e "${GREEN}✓ SecretFinder installed${NC}"
else
    echo -e "${GREEN}✓ SecretFinder already installed${NC}"
fi

# Arjun
echo -e "${YELLOW}Installing Arjun...${NC}"
pip install arjun
echo -e "${GREEN}✓ Arjun installed${NC}"

# ParamSpider
if [ ! -d "ParamSpider" ]; then
    echo -e "${YELLOW}Installing ParamSpider...${NC}"
    git clone https://github.com/devanshbatham/ParamSpider.git
    cd ParamSpider
    pip install -r requirements.txt
    cd ..
    echo -e "${GREEN}✓ ParamSpider installed${NC}"
else
    echo -e "${GREEN}✓ ParamSpider already installed${NC}"
fi

# SubJS
if [ ! -d "SubJS" ]; then
    echo -e "${YELLOW}Installing SubJS...${NC}"
    git clone https://github.com/lc/subjs.git SubJS
    cd SubJS
    go build
    cd ..
    echo -e "${GREEN}✓ SubJS installed${NC}"
else
    echo -e "${GREEN}✓ SubJS already installed${NC}"
fi

echo ""
echo "📚 Downloading wordlists"

WORDLIST_DIR="$(pwd)/../data/wordlists"
mkdir -p "$WORDLIST_DIR"
cd "$WORDLIST_DIR"

# SecLists
if [ ! -d "SecLists" ]; then
    echo -e "${YELLOW}Cloning SecLists (this may take a while)...${NC}"
    git clone --depth 1 https://github.com/danielmiessler/SecLists.git
    echo -e "${GREEN}✓ SecLists downloaded${NC}"
else
    echo -e "${GREEN}✓ SecLists already exists${NC}"
fi

# DNS resolvers
if [ ! -f "resolvers.txt" ]; then
    echo -e "${YELLOW}Downloading trusted DNS resolvers...${NC}"
    wget -q https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt -O resolvers.txt
    echo -e "${GREEN}✓ DNS resolvers downloaded${NC}"
else
    echo -e "${GREEN}✓ DNS resolvers already exist${NC}"
fi

echo ""
echo "=================================="
echo -e "${GREEN}✅ Installation Complete!${NC}"
echo ""
echo "📝 Summary:"
echo "  - Tools installed to: $TOOLS_DIR"
echo "  - Wordlists downloaded to: $WORDLIST_DIR"
echo ""
echo "⚠️  Important:"
echo "  - Add Go bin to PATH if not already: export PATH=\$PATH:\$(go env GOPATH)/bin"
echo "  - Some tools may require API keys (subfinder, amass)"
echo "  - Check individual tool documentation for configuration"
echo ""
echo "🎯 Next steps:"
echo "  1. Configure API keys in config/settings.yaml"
echo "  2. Run 'python cli.py --help' to start using ReconXploit"
echo ""
