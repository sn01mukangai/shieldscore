FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Install Go (for subfinder/httpx/nuclei)
RUN curl -sL https://go.dev/dl/go1.22.0.linux-amd64.tar.gz | tar -C /usr/local -xzf -
ENV PATH=$PATH:/usr/local/go/bin:/root/go/bin

# Install recon tools
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000
CMD ["python", "app.py"]
