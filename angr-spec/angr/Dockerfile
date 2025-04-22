FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/root/.local/bin:$PATH"

# Install system packages
RUN apt-get update && apt-get install -y \
    git python3 python3-pip python3-venv \
    build-essential libffi-dev libssl-dev \
    libglib2.0-dev libpixman-1-dev \
    cmake libreadline-dev libxml2-dev libxslt1-dev \
    binutils-multiarch nasm \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Create virtualenv + install angr
RUN python3 -m venv /opt/angr-venv && \
    /opt/angr-venv/bin/pip install --upgrade pip && \
    /opt/angr-venv/bin/pip install angr

# Launch shell with venv activated
CMD ["/bin/bash"]
