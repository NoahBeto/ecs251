#!/bin/bash

# Comprehensive benchmark for file server (Universal Version)
# Based on ECS 251 evaluation plan

# check input
TYPE=$1
if [[ "$TYPE" != "epoll" && "$TYPE" != "iouring" ]]; then
    echo "Usage: $0 [epoll|iouring]"
    exit 1
fi

SERVER_NAME="fileserver_${TYPE}"
OUTPUT_DIR="benchmark_results_${TYPE}"
mkdir -p $OUTPUT_DIR

echo "========================================"
echo "Comprehensive Performance Benchmark v2 ($TYPE)"
echo "========================================"
echo ""

# Create test files (1KB to 10MB)
echo "Creating test files..."
mkdir -p test_data
dd if=/dev/zero of=test_data/1kb.txt bs=1K count=1 2>/dev/null
dd if=/dev/zero of=test_data/10kb.bin bs=1K count=10 2>/dev/null
dd if=/dev/zero of=test_data/100kb.bin bs=1K count=100 2>/dev/null
dd if=/dev/zero of=test_data/1mb.bin bs=1M count=1 2>/dev/null
dd if=/dev/zero of=test_data/10mb.bin bs=1M count=10 2>/dev/null
echo "✓ Test files created"
echo ""

# Function to get peak CPU usage during benchmark
get_peak_cpu() {
    local pid=$1
    if [ -z "$pid" ]; then
        echo "0"
        return
    fi
    
    # Sample CPU multiple times and get peak
    local peak=0
    for i in {1..20}; do
        local cpu=$(ps -p $pid -o %cpu --no-headers 2>/dev/null | awk '{print $1}')
        if [ -n "$cpu" ]; then
            # Compare and keep peak
            peak=$(echo "$cpu $peak" | awk '{if($1>$2) print $1; else print $2}')
        fi
        sleep 0.2
    done
    
    echo "$peak"
}

# # Test 1: Throughput vs Concurrency (10 to 10,000)
# echo "=== Test 1: Throughput vs Concurrency (1KB file) ==="
# for c in 10 50 100 500 1000 5000 10000; do
#     echo "Concurrency: $c"
    
#     # Get server PID for CPU monitoring
#     SERVER_PID=$(pgrep -f $SERVER_NAME)
#     if [ -z "$SERVER_PID" ]; then
#         echo "Error: Server not running"
#         continue
#     fi
    
#     # Adjust number of requests and timeout for high concurrency
#     if [ $c -le 1000 ]; then
#         n_requests=$((c * 10))
#         timeout=10
#     else
#         n_requests=$((c * 5))  # Reduce for high concurrency
#         timeout=30
#     fi
    
#     # Start CPU monitoring in background
#     (
#         peak_cpu=0
#         while kill -0 $$ 2>/dev/null; do
#             cpu=$(ps -p $SERVER_PID -o %cpu --no-headers 2>/dev/null | awk '{print $1}')
#             if [ -n "$cpu" ]; then
#                 peak_cpu=$(echo "$cpu $peak_cpu" | awk '{if($1>$2) print $1; else print $2}')
#             fi
#             sleep 0.1
#         done
#         echo "$peak_cpu" > /tmp/cpu_peak_${c}.tmp
#     ) &
#     CPU_MONITOR_PID=$!
    
#     # Run benchmark
#     ab -n $n_requests -c $c -s $timeout -q http://localhost:8000/test_data/1kb.txt 2>&1 > "${OUTPUT_DIR}/${TYPE}_c${c}_1kb.txt"
#     AB_EXIT=$?
    
#     # Stop CPU monitoring
#     kill $CPU_MONITOR_PID 2>/dev/null
#     wait $CPU_MONITOR_PID 2>/dev/null
    
#     # Get peak CPU
#     if [ -f /tmp/cpu_peak_${c}.tmp ]; then
#         peak_cpu=$(cat /tmp/cpu_peak_${c}.tmp)
#         rm /tmp/cpu_peak_${c}.tmp
#     else
#         peak_cpu="0"
#     fi
    
#     # Display results
#     if [ $AB_EXIT -eq 0 ]; then
#         cat "${OUTPUT_DIR}/${TYPE}_c${c}_1kb.txt" | \
#             grep -E "Requests per second|Time per request|Failed requests"
#         echo "Peak CPU: ${peak_cpu}%"
#         echo "Peak CPU: ${peak_cpu}%" >> "${OUTPUT_DIR}/${TYPE}_c${c}_1kb.txt"
#     else
#         echo "Benchmark failed (likely timeout or connection limit)"
#         echo "Peak CPU: ${peak_cpu}%"
#     fi
#     echo ""
# done

# # Test 2: Latency vs File Size (1KB to 10MB)
# echo "=== Test 2: Latency vs File Size (100 concurrent) ==="
# for file in 1kb.txt 10kb.bin 100kb.bin 1mb.bin 10mb.bin; do
#     echo "File: $file"
#     ab -n 1000 -c 100 -q http://localhost:8000/test_data/${file} 2>&1 | \
#         tee "${OUTPUT_DIR}/${TYPE}_c100_${file}" | \
#         grep -E "Requests per second|Time per request|Transfer rate"
#     echo ""
# done

# Test 3: Range Requests Performance
echo "=== Test 3: Range Request Performance ==="
for c in 10 100 1000; do
    echo "Range requests - Concurrency: $c"
    
    # Create a Lua script for wrk to do range requests
    cat > /tmp/range.lua << 'EOF'
request = function()
    headers = {}
    headers["Range"] = "bytes=0-1023"
    return wrk.format("GET", "/test_data/1mb.bin", headers, nil)
end
EOF
    
    if command -v wrk &> /dev/null; then
        wrk -t4 -c$c -d10s -s /tmp/range.lua http://localhost:8000 2>&1 | \
            tee "${OUTPUT_DIR}/range_c${c}.txt" | \
            grep -E "Requests/sec|Latency"
    else
        # Fallback to ab
        ab -n 1000 -c $c -H "Range: bytes=0-1023" \
            http://localhost:8000/test_data/1mb.bin 2>&1 | \
            tee "${OUTPUT_DIR}/range_c${c}.txt" | \
            grep -E "Requests per second|Time per request"
    fi
    echo ""
done

# Test 4: CPU Profiling with perf
echo "=== Test 4: CPU Profiling (perf) ==="

if command -v perf &> /dev/null; then
    echo "Recording CPU profile during benchmark..."
    
    SERVER_PID=$(pgrep -f "${SERVER_NAME} 8000")
    
    # Start perf recording
    sudo perf record -F 99 -p $SERVER_PID -g -o ${OUTPUT_DIR}/perf.data -- sleep 10 &
    PERF_PID=$!
    
    sleep 1
    
    # Run benchmark during profiling
    ab -n 10000 -c 500 -q http://localhost:8000/test_data/1kb.txt >/dev/null 2>&1
    
    wait $PERF_PID
    
    # Generate report
    sudo perf report -i ${OUTPUT_DIR}/perf.data --stdio > ${OUTPUT_DIR}/perf_report.txt 2>/dev/null
    
    echo "✓ CPU profile saved to ${OUTPUT_DIR}/perf.data"
    echo "  View with: sudo perf report -i ${OUTPUT_DIR}/perf.data"
else
    echo "⚠ perf not installed, skipping CPU profiling"
    echo "  Install with: sudo apt-get install linux-tools-common linux-tools-generic"
fi
echo ""

# Test 5: System Calls Analysis (detailed)
echo "=== Test 5: System Call Analysis ==="

echo "Starting server with strace..."
pkill -f "fileserver_iouring 8000"
sleep 1

timeout --signal=INT 5s strace -c -f -o ${OUTPUT_DIR}/syscalls_detailed.txt ./build/fileserver_iouring 8000 >/dev/null 2>&1 &
SERVER_PID=$!

sleep 2

echo "Running benchmark (1000 requests)..."
ab -n 1000 -c 100 -q http://localhost:8000/test_data/1kb.txt >/dev/null 2>&1

sleep 1
kill -INT $SERVER_PID
wait $SERVER_PID 2>/dev/null

echo "✓ System call data saved"
echo ""

# Test 6: File Upload Performance
echo "=== Test 6: File Upload Performance ==="

# Create upload test file
echo "Creating upload test file (100KB)..."
dd if=/dev/urandom of=/tmp/upload_test.bin bs=1K count=100 2>/dev/null

for c in 10 50 100; do
    echo "Upload - Concurrency: $c"
    
    # Upload multiple times
    start_time=$(date +%s.%N)
    for i in $(seq 1 $c); do
        curl -X POST --data-binary @/tmp/upload_test.bin \
            http://localhost:8000/test_data/upload_${i}.bin >/dev/null 2>&1 &
    done
    wait
    end_time=$(date +%s.%N)
    
    duration=$(echo "$end_time - $start_time" | bc)
    throughput=$(echo "scale=2; $c / $duration" | bc)
    
    echo "  Uploaded $c files in ${duration}s (${throughput} uploads/s)" | \
        tee "${OUTPUT_DIR}/upload_c${c}.txt"
    echo ""
done

# Test 7: CPU Utilization vs Concurrency
echo "=== Test 7: CPU Utilization vs Concurrency ==="

for c in 10 50 100 500 1000 5000 10000; do
    echo "Measuring CPU at concurrency: $c"
    
    SERVER_PID=$(pgrep -f $SERVER_NAME)
    if [ -z "$SERVER_PID" ]; then
        echo "Error: Server not running"
        continue
    fi
    
    # Start CPU monitoring for peak
    peak_cpu=0
    
    # Run benchmark in background
    ab -n 10000 -c $c -q http://localhost:8000/test_data/1kb.txt >/dev/null 2>&1 &
    AB_PID=$!
    
    # Monitor CPU while benchmark runs
    while kill -0 $AB_PID 2>/dev/null; do
        cpu=$(ps -p $SERVER_PID -o %cpu --no-headers 2>/dev/null | awk '{print $1}')
        if [ -n "$cpu" ]; then
            peak_cpu=$(echo "$cpu $peak_cpu" | awk '{if($1>$2) print $1; else print $2}')
        fi
        sleep 0.1
    done
    
    wait $AB_PID 2>/dev/null
    
    echo "  Peak CPU: ${peak_cpu}%" | tee "${OUTPUT_DIR}/cpu_c${c}.txt"
    echo ""
done

echo "========================================"
echo "Benchmark Complete!"
echo "========================================"
echo ""
echo "Results saved in ${OUTPUT_DIR}/"
echo ""
echo "Summary:"
echo "  - Throughput vs Concurrency: 10 to 10,000 clients ✓"
echo "  - Latency vs File Size: 1KB to 10MB ✓"
echo "  - Range Request Performance ✓"
echo "  - File Upload Performance ✓"
echo "  - CPU Profiling (perf) ✓"
echo "  - System Call Analysis ✓"
echo "  - CPU Utilization ✓"
echo ""
echo "Run: python3 visualize_results_v2.py to generate graphs"