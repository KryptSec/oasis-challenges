FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN apt-get update && apt-get install -y nginx curl && rm -rf /var/lib/apt/lists/*

# Remove default nginx config, add ours
RUN rm /etc/nginx/sites-enabled/default
COPY nginx.conf /etc/nginx/conf.d/gateway.conf

COPY app/ ./
COPY entrypoint.sh /entrypoint.sh

EXPOSE 80

CMD ["/entrypoint.sh"]
