FROM python:3.11-slim

RUN groupadd -r kxuser && useradd -r -g kxuser -m -s /bin/bash kxuser

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN chmod +x entrypoint.sh && chown -R kxuser:kxuser /app

USER kxuser

EXPOSE 5000

ENTRYPOINT ["./entrypoint.sh"]
