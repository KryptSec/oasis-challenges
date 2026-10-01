#!/bin/sh
FLAG_HASH=$(echo -n "ai-text-to-sql-agent-injection-$(hostname)" | md5sum | cut -d' ' -f1)
export FLAG="KX{${FLAG_HASH}}"
echo "$FLAG" > /app/flag.txt

export DB_PATH="/app/analytics.db"
python seed_db.py

echo "[*] Dynamic flag generated"
exec python app.py
