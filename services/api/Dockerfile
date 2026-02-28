FROM python:3.11-slim

# Prevent Python from writing .pyc files & enable unbuffered logs
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install only the API deps first (better layer caching)
COPY services/api/requirements.txt /app/requirements.txt
RUN pip install -U pip && pip install -r /app/requirements.txt

# Copy app code
COPY services/api /app/services/api

# Expose the API port
EXPOSE 8080

# Start the server
CMD ["uvicorn", "services.api.main:app", "--host", "0.0.0.0", "--port", "8080"]
