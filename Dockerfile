FROM python:3.11-slim

# Install nmap and required utilities
RUN apt-get update && apt-get install -y \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy application files
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY wsgi.py .
COPY templates/ ./templates/

# Expose port
EXPOSE 5000

# Run with Gunicorn (production WSGI server)
# Increased timeout to 300s for long nmap scans
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "300", "--access-logfile", "-", "wsgi:app"]
