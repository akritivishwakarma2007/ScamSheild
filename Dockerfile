# Use official lightweight Python 3.11 image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy requirements first (better caching)
COPY requirements.txt .

# Install dependencies using python -m pip (safe way)
RUN python -m pip install --no-cache-dir --upgrade pip && \
    python -m pip install --no-cache-dir -r requirements.txt

# Copy your entire project
COPY . .

# Expose port (App Runner maps external traffic here)
EXPOSE 8000

# Run FastAPI with uvicorn – must use $PORT env var
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "$PORT"]
