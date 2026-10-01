FROM python:3.11-slim

RUN useradd -m -s /bin/bash kxuser

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

COPY app/ ./
RUN chown -R kxuser:kxuser /app

USER kxuser

EXPOSE 5000

CMD ["python", "main.py"]
