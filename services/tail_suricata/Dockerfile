FROM python:3.11-slim
WORKDIR /app
COPY services/tail_suricata/requirements.txt /app/requirements.txt
RUN pip install -U pip && pip install -r /app/requirements.txt
COPY services/tail_suricata /app/services/tail_suricata
ENV PYTHONUNBUFFERED=1
CMD ["python", "-u", "services/tail_suricata/main.py"]