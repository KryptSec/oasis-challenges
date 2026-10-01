FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN useradd -m -s /bin/bash kxuser

COPY app/ ./app/
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

RUN chown -R kxuser:kxuser /app

USER kxuser

EXPOSE 8000

ENTRYPOINT ["./entrypoint.sh"]
