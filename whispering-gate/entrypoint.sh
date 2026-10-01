#!/bin/sh
FLAG_HASH=$(echo -n "whispering-gate-$(hostname)" | md5sum | cut -d' ' -f1)
export FLAG="KX{${FLAG_HASH}}"
echo "$FLAG" > /flag.txt
chown kxuser:kxuser /flag.txt
chmod 600 /flag.txt
echo "[*] Flag generated"
echo "[*] Starting Bramble the Gate Sentinel as kxuser on :5000"
exec su -s /bin/sh kxuser -c 'exec python /app/app.py'
