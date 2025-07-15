# RAG Security Scanner Docker Image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY src/ ./src/
COPY config.json .
COPY LICENSE .
COPY README.md .

# Create reports directory
RUN mkdir -p reports

# Set Python path
ENV PYTHONPATH=/app/src

# Set default working directory for reports
WORKDIR /app

# Default command
ENTRYPOINT ["python", "src/rag_scanner.py"]
CMD ["--demo", "--format", "html"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "from src.rag_scanner import RAGSecurityScanner; print('OK')" || exit 1

# Labels
LABEL maintainer="Oleg Nazarov <oleg@olegnazarov.com>"
LABEL description="RAG Security Scanner - Automated security testing tool for RAG systems"
LABEL version="1.0.0"
LABEL source="https://github.com/olegnazarov/rag-security-scanner"