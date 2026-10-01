#!/bin/sh
FLAG_HASH=$(echo -n "ai-confused-deputy-email-agent-$(hostname)" | md5sum | cut -d' ' -f1)
export FLAG="KX{${FLAG_HASH}}"
echo "$FLAG" > /app/flag.txt
echo "[*] Dynamic flag generated"
exec python app.py
