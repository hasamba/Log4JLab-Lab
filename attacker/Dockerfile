FROM kalilinux/kali-rolling

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    curl \
    netcat-traditional \
    nmap \
    yara \
    nuclei \
    git \
    vim \
    && rm -rf /var/lib/apt/lists/*

# Install Python packages
RUN pip3 install requests colorama

# Install Sigma tools
RUN pip3 install sigma-cli pySigma

WORKDIR /tools

# Copy exploitation and detection scripts
COPY exploit.py .
COPY detect.py .
COPY listener.py .

RUN chmod +x *.py

WORKDIR /detection-rules

CMD ["/bin/bash"]