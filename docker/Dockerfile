FROM python:3.11-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    curl \
    ruby \
    dnsutils \
    zip \
    xxd \
    gcc \
    libc-dev \
    openssh-client \
    procps \
    iproute2 \
    mount \
    binutils \
    && rm -rf /var/lib/apt/lists/*

# Copy detection scripts
COPY scripts/ /opt/scripts/
COPY run-all.sh /opt/scripts/run-all.sh
RUN chmod +x /opt/scripts/*.sh /opt/scripts/run-all.sh

# Embed EICAR test string (used by script 16)
RUN echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /opt/scripts/eicar.com.txt

WORKDIR /opt/scripts

ENTRYPOINT ["/bin/bash"]
