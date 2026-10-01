#!/bin/sh
FLAG_HASH=$(echo -n "ai-system-prompt-$(hostname)" | md5sum | cut -d' ' -f1)
export FLAG="KX{${FLAG_HASH}}"
echo "$FLAG" > /app/flag.txt
echo "[*] Dynamic flag generated"
exec uvicorn app.main:app --host 0.0.0.0 --port 8000
