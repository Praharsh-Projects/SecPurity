FROM python:3.11-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1
COPY services/feed_kev/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY services/feed_kev/ ./
CMD ["python", "-u", "main.py"]