FROM python:3.11-slim

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

# Install CA certificates and Android Asset Packaging Tool (aapt)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    aapt \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt pyproject.toml /app/
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Pre-create all required directories and ensure writable permissions
RUN mkdir -p /app/ucsd /app/tests /app/samples /app/reports /app/data /app/data/db /app/workspace /app/demo /app/frontend/dist && \
    chmod -R 777 /app/reports /app/data /app/workspace

# Copy repository code
COPY ucsd /app/ucsd
COPY tests /app/tests
COPY demo /app/demo
COPY frontend/dist /app/frontend/dist

# Expose API and Web UI port
EXPOSE 8000

# Default command for the container
CMD ["uvicorn", "ucsd.server.app:app", "--host", "0.0.0.0", "--port", "8000"]
