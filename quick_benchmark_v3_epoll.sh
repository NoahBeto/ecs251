#!/bin/bash

OUTPUT_DIR="benchmark_results_epoll"
mkdir -p $OUTPUT_DIR

echo "========================================"
echo "Comprehensive Performance Benchmark v2 (epoll)"
echo "========================================"
echo ""

# --- Create test files ---
echo "Creating test files..."
mkdir -p test_data
dd if=/dev/zero of=test_data/1kb.txt bs=1K count=1 2>/dev/null
dd if=/dev/zero of=test_data/10kb.bin bs=1K count=10 2>/dev/null
dd if=/dev/zero of/test_data/100kb.bin bs=1K count=100 2>/dev/null
dd if=/dev/zero of/test_data/1mb.bin bs=1M count=1 2>/dev/null
dd if=/dev/zero of/test_data/10mb.bin bs=1M count=10 2>/dev/null
echo "✓ Test files created"
echo ""

# --- Function: monitor CPU during benchmark ---
monitor_cpu() {
    local pid=$1
    local ab_pid=$2
    local outfile=$3
    (
        peak_cpu=0
        while kill -0 $ab_pid 2>/dev/null; do
            cpu=$(ps -p $pid -o %cpu --no-headers 2>/dev/null | awk '{print $1}')
            if [ -n "$cpu" ]; then
                peak_cpu=$(echo "$cpu $peak_cpu" | awk '{if($1>$2) print $1; else print $2}')
            fi
            sleep 0.1
        done
        echo "$peak_cpu" > "$outfile"
    ) &
    echo $!  # return background PID
}

# --- Test 1: Throughput vs Concurrency ---
echo "=== Test 1: Throughput vs Concurrency (1KB file) ==="
for c in 10 50 100 500 1000 5000 10000; do
    echo "Concurrency: $c"
    
    SERVER_PID=$(pgrep -f fileserver_epoll)
    if [ -z "$SERVER_PID" ]; then
        echo "Error: Server not running"
        continue
    fi
    
    if [ $c -le 1000 ]; then
        n_requests=$((c * 10))
        timeout=10
    else
        n_requests=$((c * 5))
        timeout=30
    fi
    
    ab -n $n_requests -c $c -s $timeout -q http://localhost:8000/test_data/1kb.txt \
        > "${OUTPUT_DIR}/epoll_c${c}_1kb.txt" 2>&1 &
    AB_PID=$!
    
    CPU_MONITOR_PID=$(monitor_cpu $SERVER_PID $AB_PID "/tmp/cpu_peak_${c}.tmp")
    
    wait $AB_PID 2>/dev/null
    kill $CPU_MONITOR_PID 2>/dev/null
    
    if [ -f /tmp/cpu_peak_${c}.tmp ]; then
        peak_cpu=$(cat /tmp/cpu_peak_${c}.tmp)
        rm /tmp/cpu_peak_${c}.tmp
    else
        peak_cpu="0"
    fi
    
    echo "Peak CPU: ${peak_cpu}%" >> "${OUTPUT_DIR}/epoll_c${c}_1kb.txt"
    grep -E "Requests per second|Time per request|Failed requests" "${OUTPUT_DIR}/epoll_c${c}_1kb.txt"
    echo "Peak CPU: ${peak_cpu}%"
    echo ""
done

# --- Test 2: Latency vs File Size (100 concurrent) ---
echo "=== Test 2: Latency vs File Size (100 concurrent) ==="
for file in 1kb.txt 10kb.bin 100kb.bin 1mb.bin 10mb.bin; do
    echo "File: $file"
    ab -n 1000 -c 100 -q http://localhost:8000/test_data/${file} 2>&1 | \
        tee "${OUTPUT_DIR}/epoll_c100_${file}" | \
        grep -E "Requests per second|Time per request|Transfer rate"
    echo ""
done

# --- Test 3: Range Requests Performance ---
echo "=== Test 3: Range Request Performance ==="
for c in 10 100 1000; do
    echo "Range requests - Concurrency: $c"
    ab -n 1000 -c $c -H "Range: bytes=0-1023" \
        http://localhost:8000/test_data/1mb.bin 2>&1 | \
        tee "${OUTPUT_DIR}/range_c${c}.txt" | \
        grep -E "Requests per second|Time per request"
    echo ""
done

# --- Test 4: CPU Profiling (perf) ---
echo "=== Test 4: CPU Profiling (perf) ==="
echo "⚠ Skipping perf recording for Python visualization compatibility"
echo ""

# --- Test 5: System Calls Analysis ---
echo "=== Test 5: System Call Analysis ==="
strace -c -f -o ${OUTPUT_DIR}/syscalls_detailed.txt ./build/fileserver_epoll 8000 &
SERVER_PID=$!
sleep 2
ab -n 1000 -c 100 -q http://localhost:8000/test_data/1kb.txt >/dev/null 2>&1
kill -INT $SERVER_PID
wait $SERVER_PID 2>/dev/null
echo "✓ System call data saved"
echo ""

# --- Test 6: File Upload Performance ---
echo "=== Test 6: File Upload Performance ==="
dd if=/dev/urandom of=/tmp/upload_test.bin bs=1K count=100 2>/dev/null
for c in 10 50 100; do
    echo "Upload - Concurrency: $c"
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

# --- Test 7: CPU Utilization vs Concurrency ---
echo "=== Test 7: CPU Utilization vs Concurrency ==="
for c in 10 50 100 500 1000 5000 10000; do
    echo "Measuring CPU at concurrency: $c"
    
    SERVER_PID=$(pgrep -f fileserver_epoll)
    if [ -z "$SERVER_PID" ]; then
        echo "Error: Server not running"
        continue
    fi
    
    ab -n 10000 -c $c -q http://localhost:8000/test_data/1kb.txt >/dev/null 2>&1 &
    AB_PID=$!
    
    CPU_MONITOR_PID=$(monitor_cpu $SERVER_PID $AB_PID "/tmp/cpu_peak_${c}.tmp")
    
    wait $AB_PID 2>/dev/null
    kill $CPU_MONITOR_PID 2>/dev/null
    
    if [ -f /tmp/cpu_peak_${c}.tmp ]; then
        peak_cpu=$(cat /tmp/cpu_peak_${c}.tmp)
        rm /tmp/cpu_peak_${c}.tmp
    else
        peak_cpu="0"
    fi
    
    echo "Peak CPU: ${peak_cpu}%" > "${OUTPUT_DIR}/cpu_c${c}.txt"
    echo "Peak CPU: ${peak_cpu}%"
    echo ""
done

echo "========================================"
echo "Benchmark Complete!"
echo "========================================"
echo ""
echo "Results saved in ${OUTPUT_DIR}/"
echo ""
echo "Run: python3 visualize_results_v2.py to generate graphs"