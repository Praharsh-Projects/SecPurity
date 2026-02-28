FROM python:3.11-slim
WORKDIR /app
COPY services/evaluator/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY services/evaluator /app/services/evaluator
ENV PYTHONUNBUFFERED=1
CMD ["python", "-u", "services/evaluator/main.py"]
