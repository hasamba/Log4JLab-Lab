FROM kalilinux/kali-rolling

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-requests \
    python3-colorama \
    curl \
    netcat-traditional \
    nmap \
    yara \
    nuclei \
    git \
    vim \
    pipx \
    && rm -rf /var/lib/apt/lists/*

# Use pipx for Sigma tools (or install via apt if available)
RUN pipx install sigma-cli || pip3 install --break-system-packages sigma-cli pySigma

WORKDIR /tools

# Copy exploitation and detection scripts
COPY exploit.py .
COPY detect.py .
COPY listener.py .

RUN chmod +x *.py

WORKDIR /detection-rules

CMD ["/bin/bash"]