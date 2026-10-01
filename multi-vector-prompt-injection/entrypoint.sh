#!/bin/sh
FLAG_HASH=$(echo -n "multi-vector-injection-$(hostname)" | md5sum | cut -d' ' -f1)
export FLAG="KX{${FLAG_HASH}}"
echo "$FLAG" > /app/flag.txt

SERVICE_TOKEN=$(echo -n "briefai-internal-svc-$(hostname)" | md5sum | cut -d' ' -f1)
export INTERNAL_SERVICE_TOKEN="${SERVICE_TOKEN}"

echo "[*] Dynamic flag generated"
echo "[*] Internal service token configured"
exec uvicorn app.main:app --host 0.0.0.0 --port 8000
