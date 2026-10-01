#!/bin/sh
FLAG_HASH=$(echo -n "mcp-eval-rce-$(hostname)" | md5sum | cut -d' ' -f1)
FLAG="KX{${FLAG_HASH}}"
# The flag lives on the server filesystem; the RCE reads it. kxuser owns it and the
# MCP server runs as kxuser, so the eval sink can read it.
echo "$FLAG" > /flag.txt
chown kxuser:kxuser /flag.txt
chmod 600 /flag.txt

echo "[*] Flag generated"
echo "[*] Starting Tinker (MCP host + workshop MCP server) as kxuser on :5000"
exec su -s /bin/sh kxuser -c 'exec python /app/app.py'
