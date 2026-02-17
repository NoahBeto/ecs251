#!/bin/bash

# Analyze system calls for io_uring file server

echo "=== System Call Analysis ==="
echo ""

# Start server with strace
echo "Starting server with strace..."
strace -c -f -o syscalls_summary.txt ./build/fileserver_iouring 8000 &
SERVER_PID=$!

sleep 2

# Run benchmark
echo "Running benchmark (100 requests)..."
ab -n 100 -c 10 -q http://localhost:8000/test_data/1kb.txt >/dev/null 2>&1

# Stop server
echo "Stopping server..."
kill -INT $SERVER_PID
wait $SERVER_PID 2>/dev/null

echo ""
echo "=== System Call Summary ==="
cat syscalls_summary.txt

echo ""
echo "Key metrics:"
grep -E "io_uring_enter|io_uring_setup|epoll|read|write|open" syscalls_summary.txt || echo "No matching syscalls found"

echo ""
echo "Full output saved to syscalls_summary.txt"
