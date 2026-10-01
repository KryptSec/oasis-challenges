#!/bin/bash

FLAG_HASH=$(echo -n "ai-rag-poisoning-$(hostname)" | md5sum | cut -d' ' -f1)
export CTF_FLAG="KX{$FLAG_HASH}"
echo "KX{$FLAG_HASH}" > /app/flag.txt

echo "[*] ResearchBot starting..."
echo "[*] Flag generated successfully."

exec uvicorn app.main:app --host 0.0.0.0 --port 8000
