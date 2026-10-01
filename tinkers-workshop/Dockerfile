FROM python:3.11-slim

RUN adduser --disabled-password --gecos '' kxuser

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py mcp_server.py ./
COPY templates/ ./templates/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && chown -R kxuser:kxuser /app

ENV PYTHONUNBUFFERED=1
EXPOSE 5000

ENTRYPOINT ["/entrypoint.sh"]
