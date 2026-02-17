#!/bin/bash

# Quick performance test for io_uring file server
# Run this while server is running on port 8000

OUTPUT_DIR="benchmark_results"
mkdir -p $OUTPUT_DIR

echo "=== Quick Performance Test ==="
echo ""

# Create test files
mkdir -p test_data
echo "Creating test files..."
dd if=/dev/zero of=test_data/1kb.txt bs=1K count=1 2>/dev/null
dd if=/dev/zero of=test_data/10kb.bin bs=1K count=10 2>/dev/null
dd if=/dev/zero of=test_data/100kb.bin bs=1K count=100 2>/dev/null
dd if=/dev/zero of=test_data/1mb.bin bs=1M count=1 2>/dev/null

echo "Testing io_uring server..."
echo ""

# Test different concurrency levels
for c in 10 50 100 500 1000; do
    echo "Concurrency: $c"
    ab -n 10000 -c $c -q http://localhost:8000/test_data/1kb.txt 2>&1 | \
        tee "${OUTPUT_DIR}/iouring_c${c}_1kb.txt" | \
        grep -E "Requests per second|Time per request|Failed"
    echo ""
done

# Test different file sizes
echo "Testing different file sizes (c=100):"
for file in 1kb.txt 10kb.bin 100kb.bin 1mb.bin; do
    echo "File: $file"
    ab -n 1000 -c 100 -q http://localhost:8000/test_data/${file} 2>&1 | \
        tee "${OUTPUT_DIR}/iouring_c100_${file}" | \
        grep -E "Requests per second|Time per request"
    echo ""
done

echo "Results saved in $OUTPUT_DIR/"
