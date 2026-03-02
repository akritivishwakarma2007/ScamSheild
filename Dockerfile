# Use official Python slim image (lightweight, secure)
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy only requirements first → better caching
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of your application code
COPY . .

# Expose the port (App Runner will map external traffic to this)
EXPOSE 8000

# Run the app with uvicorn
# Important: use $PORT environment variable that App Runner provides
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "$PORT"]
