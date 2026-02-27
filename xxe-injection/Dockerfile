FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN apt-get update && apt-get install -y curl libxml2-dev libxslt-dev && rm -rf /var/lib/apt/lists/*
COPY app/ ./
EXPOSE 5000
CMD ["python", "main.py"]
