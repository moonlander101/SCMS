FROM python:3.12-slim

LABEL authors="kevin"
# Set environment vars
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Create working directory
WORKDIR /app

# Install OS-level dependencies (optional but often useful)
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY . /app

# Install Python dependencies
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# Expose FastAPI port
EXPOSE 8000

# Start the FastAPI app using Uvicorn
CMD ["python", "-m", "uvicorn", "gateway:app", "--host", "0.0.0.0", "--port", "8000"]
