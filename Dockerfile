FROM python:3.10-slim

LABEL maintainer="SecuriForge"
LABEL product="SecuriForge Unified Binary Analysis Platform"

# Install system dependencies including WeasyPrint requirements
RUN apt-get update && apt-get install -y \
    build-essential \
    yara \
    libmagic1 \
    libffi-dev \
    curl \
    git \
    libcairo2 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    shared-mime-info \
    fonts-dejavu \
    && rm -rf /var/lib/apt/lists/*


# Set working directory
WORKDIR /securiforge

# Copy Python dependencies and install
COPY requirements.txt .
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

CMD ["python3", "unified_binary_analysis.py", "--help"]
