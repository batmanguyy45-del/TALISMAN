FROM python:3.11-slim

LABEL maintainer="TALISMAN Project"
LABEL description="Advanced Bug Bounty & Professional Security Research Platform"

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    curl \
    wget \
    git \
    golang-go \
    libpcap-dev \
    iputils-ping \
    dnsutils \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Go tools — ProjectDiscovery suite
ENV GOPATH=/root/go
ENV PATH=$PATH:$GOPATH/bin

RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || true && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null || true && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null || true && \
    go install -v github.com/ffuf/ffuf/v2@latest 2>/dev/null || true && \
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest 2>/dev/null || true

# Install TALISMAN
WORKDIR /app
COPY pyproject.toml .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir ".[all]" || \
    pip install --no-cache-dir typer rich httpx aiodns dnspython pyyaml sqlalchemy \
        aiosqlite jinja2 beautifulsoup4 lxml tldextract cryptography pyjwt \
        python-dateutil psutil colorama tabulate mmh3 orjson aiofiles \
        tenacity structlog netaddr 2>/dev/null || true

COPY . .
RUN pip install --no-cache-dir -e . 2>/dev/null || true

# Create directories
RUN mkdir -p /root/.talisman/{sessions,wordlists,templates,plugins} && \
    mkdir -p /reports

VOLUME ["/root/.talisman", "/reports"]
ENTRYPOINT ["talisman"]
CMD ["--help"]
