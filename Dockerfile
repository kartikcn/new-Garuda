FROM python:3.11-slim

# Install dependencies
RUN apt-get update && \
    apt-get install -y nmap && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy all files
COPY . .

# Install Python dependencies
RUN pip install --no-cache-dir flask

# Expose the Flask app port
EXPOSE 8080

# Run the app
CMD ["python", "app.py"]
