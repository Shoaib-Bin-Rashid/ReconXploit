FROM python:3.11-slim

# Install system dependencies and tools
RUN apt-get update && apt-get install -y \
    wget \
    curl \
    git \
    nmap \
    masscan \
    chromium \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Go (needed for subfinder, httpx, nuclei, etc)
ENV GOLANG_VERSION=1.21.0
RUN wget https://go.dev/dl/go${GOLANG_VERSION}.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go${GOLANG_VERSION}.linux-amd64.tar.gz && \
    rm go${GOLANG_VERSION}.linux-amd64.tar.gz
ENV PATH=$PATH:/usr/local/go/bin:/root/go/bin

# Install Go-based recon tools
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/tomnomnom/assetfinder@latest && \
    go install -v github.com/owasp-amass/amass/v4/...@master && \
    go install -v github.com/lc/gau/v2/cmd/gau@latest && \
    go install -v github.com/tomnomnom/waybackurls@latest && \
    go install -v github.com/sensepost/gowitness@latest

# Install findomain
RUN wget https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux-i386.zip && \
    unzip findomain-linux-i386.zip && \
    chmod +x findomain && \
    mv findomain /usr/local/bin/ && \
    rm findomain-linux-i386.zip

# Set up project directory
WORKDIR /app
COPY backend/requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Create data directory
RUN mkdir -p /app/data

# Default command
ENTRYPOINT ["python", "reconxp.py"]
CMD ["--help"]
