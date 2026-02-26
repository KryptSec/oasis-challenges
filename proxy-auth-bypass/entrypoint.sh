#!/bin/sh
# Start Flask in the background
python /app/main.py &

# Start nginx in the foreground
nginx -g 'daemon off;'
