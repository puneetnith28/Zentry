# Use a slim version of Python for a smaller security footprint
FROM python:3.11-slim

# Set environment variables to prevent Python from writing .pyc files and buffering stdout
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/home/scanneruser/.local/bin:${PATH}"

WORKDIR /code

# Install system dependencies required for WeasyPrint and network tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    python3-dev \
    libpango-1.0-0 \
    libharfbuzz0b \
    libpangoft2-1.0-0 \
    libcairo2 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    shared-mime-info \
    libffi-dev \
    libjpeg-dev \
    libopenjp2-7-dev \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Install subfinder
RUN wget -qO /tmp/subfinder.zip https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_amd64.zip && \
    unzip -q /tmp/subfinder.zip -d /tmp && \
    mv /tmp/subfinder /usr/local/bin/subfinder && \
    chmod 755 /usr/local/bin/subfinder && \
    rm -rf /tmp/subfinder.zip /tmp/subfinder*

# Security Best Practice: Create non-root user
RUN useradd -m -u 1000 -s /bin/bash scanneruser && \
    mkdir -p /code /tmp/zentry_report_cache && \
    chown -R scanneruser:scanneruser /code /tmp/zentry_report_cache

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .
RUN chown -R scanneruser:scanneruser /code

USER scanneruser
