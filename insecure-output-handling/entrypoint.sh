#!/bin/sh
FLAG_HASH=$(echo -n "ai-insecure-output-$(hostname)" | md5sum | cut -d' ' -f1)
export FLAG="KX{${FLAG_HASH}}"
echo "$FLAG" > /app/flag.txt

ADMIN_SECRET=$(echo -n "askbot-admin-$(hostname)-secret" | md5sum | cut -d' ' -f1)
export ADMIN_SECRET="${ADMIN_SECRET}"

echo "[*] Dynamic flag generated"
echo "[*] Admin secret configured"
exec python app.py
