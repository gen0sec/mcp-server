FROM python:3.14-slim

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive

# Install required system packages
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd app --home /app \
    && mkdir -p /app \
    && chown -R app:app /app


# Set working directory
WORKDIR /app

USER app

# Copy project files
COPY server /app
COPY requirements.txt /app/requirements.txt

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

COPY manifest.json /app/manifest.json
# Expose port 8000
EXPOSE 8000

# Run the Python server
# Host 0.0.0.0 allows connections from outside the container


CMD ["python", "main.py", "--transport", "streamable-http", "--host", "0.0.0.0", "--port", "8000"]
