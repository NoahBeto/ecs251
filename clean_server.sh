#!/bin/bash

# Clean script for io_uring file server
# Run this before restarting server manually

echo "=== Cleaning Server Environment ==="
echo ""

# 1. Stop existing server
echo "1. Stopping existing server..."
pkill -9 fileserver_iouring
sleep 1
echo "   Server stopped"

# 2. Wait for port to be released
echo "2. Waiting for port 8000 to be released..."
while netstat -an | grep -q ":8000.*LISTEN"; do
    sleep 1
done
echo "   ✓ Port 8000 released"

# 3. Check TIME_WAIT connections
TIME_WAIT_COUNT=$(netstat -an | grep :8000 | grep TIME_WAIT | wc -l)
if [ $TIME_WAIT_COUNT -gt 0 ]; then
    echo "3. Found $TIME_WAIT_COUNT TIME_WAIT connections"
    if [ $TIME_WAIT_COUNT -gt 1000 ]; then
        echo "   ⚠ WARNING: High number of TIME_WAIT connections"
        echo "   Consider waiting 60s or run:"
        echo "   sudo sysctl -w net.ipv4.tcp_tw_reuse=1"
    fi
else
    echo "3. ✓ No TIME_WAIT connections"
fi

# 4. Clean temporary files
echo "4. Cleaning temporary files..."
rm -f test_data/upload_*.bin 2>/dev/null
rm -f /tmp/cpu_peak_*.tmp 2>/dev/null
echo "   ✓ Temporary files cleaned"

echo ""
echo "==================================="
echo "Environment cleaned!"
echo "==================================="
echo ""

