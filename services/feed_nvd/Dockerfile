FROM python:3.11-slim
WORKDIR /app
COPY services/feed_nvd/requirements.txt /app/requirements.txt
RUN pip install -U pip && pip install -r /app/requirements.txt
COPY services/feed_nvd /app/services/feed_nvd
ENV PYTHONUNBUFFERED=1
CMD ["python", "-u", "services/feed_nvd/main.py"]