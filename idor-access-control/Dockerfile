FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

COPY app/ ./

EXPOSE 5000
HEALTHCHECK --interval=5s --timeout=3s --retries=5 CMD curl -f http://localhost:5000/ || exit 1

CMD ["python", "main.py"]
