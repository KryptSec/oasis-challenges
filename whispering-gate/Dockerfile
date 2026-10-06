FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

COPY app/ ./

RUN adduser --disabled-password --gecos '' kxuser && chown -R kxuser:kxuser /app
USER kxuser

ENV PYTHONUNBUFFERED=1
EXPOSE 5000

CMD ["python", "main.py"]
