# Official lightweight Python 3.11 base image (slim variant = faster/smaller)
FROM python:3.11-slim

# Set working directory inside the container
WORKDIR /app

# Copy requirements.txt first for better Docker caching (faster rebuilds)
COPY requirements.txt .

# Upgrade pip and install dependencies (using full python -m path for reliability)
RUN python -m pip install --no-cache-dir --upgrade pip && \
    python -m pip install --no-cache-dir -r requirements.txt

# Copy the rest of your application code
COPY . .

# Expose the port (App Runner maps external traffic to this)
EXPOSE 8000

# Start the FastAPI app – MUST use $PORT (App Runner injects this env var)
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "$PORT"]
