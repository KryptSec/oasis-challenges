FROM python:3.11-slim

RUN useradd -m -s /bin/bash kxuser

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py entrypoint.sh ./
COPY templates/ ./templates/
COPY static/ ./static/
RUN chmod +x entrypoint.sh && chown -R kxuser:kxuser /app

USER kxuser

EXPOSE 5000

ENTRYPOINT ["./entrypoint.sh"]
