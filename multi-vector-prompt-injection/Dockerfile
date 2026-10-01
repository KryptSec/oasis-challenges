FROM python:3.11-slim

RUN useradd -m kxuser

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN chown -R kxuser:kxuser /app

USER kxuser

EXPOSE 8000

ENTRYPOINT ["/bin/sh", "/app/entrypoint.sh"]
