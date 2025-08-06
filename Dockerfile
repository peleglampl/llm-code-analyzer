# Use official Python as base image
FROM python:3.10-slim

# Set work directory
WORKDIR /app

# Copy project files into the image
COPY . .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Install Ollama (Linux)
RUN curl -fsSL https://ollama.com/install.sh | sh

# Default command: run analyzer
ENTRYPOINT ["python", "analyzer.py"]
