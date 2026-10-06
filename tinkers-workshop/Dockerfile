FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

COPY app/ ./

# Run as a non-root user. The flag file is pre-created here and owned by kxuser
# so the app (which runs as kxuser and generates the flag into it at startup)
# can write it, while it still lives at /flag.txt — the path the eval() RCE reads.
RUN adduser --disabled-password --gecos '' kxuser \
    && touch /flag.txt \
    && chown kxuser:kxuser /flag.txt \
    && chmod 600 /flag.txt \
    && chown -R kxuser:kxuser /app
USER kxuser

ENV PYTHONUNBUFFERED=1
EXPOSE 5000

CMD ["python", "main.py"]
