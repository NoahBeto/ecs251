#!/bin/bash

# Benchmark for epoll file server - 10MB FILE ONLY
# Based on ECS 251 evaluation plan

OUTPUT_DIR="benchmark_results_epoll_10MB"
mkdir -p $OUTPUT_DIR

echo "========================================"
echo "10MB File Performance Benchmark"
echo "========================================"
echo ""

# Create test files
echo "Creating test files..."
mkdir -p test_data
dd if=/dev/zero of=test_data/1kb.txt  bs=1K count=1   2>/dev/null
dd if=/dev/zero of=test_data/10kb.txt bs=1K count=10  2>/dev/null
dd if=/dev/zero of=test_data/100kb.txt bs=1K count=100 2>/dev/null
dd if=/dev/zero of=test_data/1mb.txt  bs=1M count=1   2>/dev/null
dd if=/dev/zero of=test_data/10mb.txt bs=1M count=10  2>/dev/null
echo "✓ Test files created"
echo ""

# ---------------------------------------------------------------
# Helper: measure peak instantaneous CPU% of a pid while a
# background job runs, using pidstat (1-second samples).
# Usage: measure_cpu_during <server_pid> <bg_job_pid>
# Prints peak CPU% to stdout.
# ---------------------------------------------------------------
measure_cpu_during() {
    local server_pid=$1
    local job_pid=$2
    local peak=0

    # pidstat -p <pid> 1 prints a new line every second with current CPU%
    pidstat -p "$server_pid" 1 2>/dev/null | while read line; do
        # pidstat output: Time  UID  PID  %usr  %system  %guest  %wait  %CPU  CPU  Command
        cpu=$(echo "$line" | awk -v pid="$server_pid" '$3==pid {print $8}')
        if [ -n "$cpu" ]; then
            peak=$(echo "$cpu $peak" | awk '{if($1>$2) print $1; else print $2}')
            echo "$peak" > /tmp/cpu_peak_running.tmp
        fi
        # stop when the benchmark job is done
        kill -0 "$job_pid" 2>/dev/null || break
    done

    local result=0
    [ -f /tmp/cpu_peak_running.tmp ] && result=$(cat /tmp/cpu_peak_running.tmp)
    rm -f /tmp/cpu_peak_running.tmp
    echo "$result"
}

# ---------------------------------------------------------------
# Test 1: Throughput vs Concurrency (10MB file)
# FIX: n_requests = max(20000, c*20) so each connection handles
#      enough requests to amortise TCP setup cost and let
#      io_uring's batching advantage show up.
# ---------------------------------------------------------------
echo "=== Test 1: Throughput vs Concurrency (10MB file) ==="
for c in 10 50 100 500 1000 5000 10000; do
    echo "Concurrency: $c"

    SERVER_PID=$(pgrep -f fileserver_epoll)
    if [ -z "$SERVER_PID" ]; then
        echo "Error: Server not running"; continue
    fi

    # Each connection handles at least 20 requests (amortises TCP setup).
    # Cap at 50000 to keep each concurrency level under ~30s.
    n_requests=$((c * 20))
    [ $n_requests -lt 20000 ] && n_requests=20000
    [ $n_requests -gt 50000 ] && n_requests=50000
    timeout=120

    echo "  Sending $n_requests requests at c=$c"

    ab -n $n_requests -c $c -s $timeout -k \
        -q http://localhost:8000/test_data/10mb.txt \
        2>&1 > "${OUTPUT_DIR}/epoll_c${c}_10mb.txt"
    AB_EXIT=$?

    if [ $AB_EXIT -eq 0 ]; then
        grep -E "Requests per second|Time per request|Failed requests" \
            "${OUTPUT_DIR}/epoll_c${c}_10mb.txt"
    else
        echo "  Benchmark failed (exit $AB_EXIT)"
    fi
    echo ""
done

# ---------------------------------------------------------------
# Test 2: Latency vs File Size (500 concurrent)
# ---------------------------------------------------------------
echo "=== Test 2: Latency vs File Size (500 concurrent) ==="
for file in 1kb.txt 10kb.txt 100kb.txt 1mb.txt 10mb.txt; do
    echo "File: $file"
    ab -n 2000 -c 500 -q \
        http://localhost:8000/test_data/${file} \
        2>&1 | tee "${OUTPUT_DIR}/epoll_c500_${file}" \
             | grep -E "Requests per second|Time per request|Transfer rate"
    echo ""
done

# ---------------------------------------------------------------
# Test 3: Range Requests Performance
# ---------------------------------------------------------------
echo "=== Test 3: Range Request Performance ==="
for c in 10 100 1000; do
    echo "Range requests - Concurrency: $c"
    if command -v wrk &>/dev/null; then
        cat > /tmp/range.lua << 'EOF'
request = function()
    headers = {}
    headers["Range"] = "bytes=0-1023"
    return wrk.format("GET", "/test_data/1mb.txt", headers, nil)
end
EOF
        wrk -t4 -c$c -d10s -s /tmp/range.lua http://localhost:8000 \
            2>&1 | tee "${OUTPUT_DIR}/range_c${c}.txt" \
                 | grep -E "Requests/sec|Latency"
    else
        ab -n 1000 -c $c -H "Range: bytes=0-1023" \
            http://localhost:8000/test_data/1mb.txt \
            2>&1 | tee "${OUTPUT_DIR}/range_c${c}.txt" \
                 | grep -E "Requests per second|Time per request"
    fi
    echo ""
done

# ---------------------------------------------------------------
# Test 4: CPU Profiling with perf
# ---------------------------------------------------------------
# echo "=== Test 4: CPU Profiling (perf) ==="
# if command -v perf &>/dev/null; then
#     SERVER_PID=$(pgrep -f "fileserver_epoll 8000")
#     sudo perf record -F 99 -p $SERVER_PID -g \
#         -o ${OUTPUT_DIR}/perf.data -- sleep 10 &
#     PERF_PID=$!
#     sleep 1
#     ab -n 10000 -c 500 -q \
#         http://localhost:8000/test_data/10mb.txt >/dev/null 2>&1
#     wait $PERF_PID
#     sudo perf report -i ${OUTPUT_DIR}/perf.data --stdio \
#         > ${OUTPUT_DIR}/perf_report.txt 2>/dev/null
#     echo "✓ CPU profile saved"
# else
#     echo "⚠ perf not installed, skipping"
# fi
# echo ""

# ---------------------------------------------------------------
# Test 5: System Call Analysis
# FIX: always kill and restart server so strace captures the
#      NEW binary (with batched submit).  Use -e trace=all to
#      count io_uring_enter separately from other syscalls.
# ---------------------------------------------------------------
echo "=== Test 5: System Call Analysis (10MB file) ==="

# --- epoll: use strace attach ---
EPOLL_PID=$(pgrep -f "fileserver_epoll")
if [ -z "$EPOLL_PID" ]; then
    echo "Error: epoll server not running"; 
else
    echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope >/dev/null

    sudo strace -c -p $EPOLL_PID \
        -o ${OUTPUT_DIR}/syscalls_detailed.txt &
    STRACE_PID=$!
    sleep 2

    echo "Running 1000 requests at c=100 (epoll)..."
    ab -n 1000 -c 100 -q \
        http://localhost:8000/test_data/1kb.txt >/dev/null 2>&1

    sleep 1
    sudo kill -INT $STRACE_PID
    wait $STRACE_PID 2>/dev/null
    echo "--- epoll syscalls ---"
    cat ${OUTPUT_DIR}/syscalls_detailed.txt
fi

# Restart clean server for remaining tests
./build/fileserver_epoll 8000 &
sleep 1

# ---------------------------------------------------------------
# Test 6: File Upload Performance
# ---------------------------------------------------------------
echo "=== Test 6: File Upload Performance ==="
dd if=/dev/urandom of=/tmp/upload_test.bin bs=1K count=100 2>/dev/null

for c in 10 50 100; do
    echo "Upload - Concurrency: $c"
    start_time=$(date +%s.%N)
    for i in $(seq 1 $c); do
        curl -s -X POST --data-binary @/tmp/upload_test.bin \
            http://localhost:8000/test_data/upload_${i}.bin &
    done
    wait
    end_time=$(date +%s.%N)
    duration=$(echo "$end_time - $start_time" | bc)
    throughput=$(echo "scale=2; $c / $duration" | bc)
    echo "  Uploaded $c files in ${duration}s (${throughput} uploads/s)" \
        | tee "${OUTPUT_DIR}/upload_c${c}.txt"
    echo ""
done

# ---------------------------------------------------------------
# Test 7: CPU Utilization vs Concurrency
# Method: read /proc/PID/stat before and after ab run.
# CPU% = (process_cpu_ticks_delta / elapsed_ticks) * 100
# This is exactly what top/htop use internally - no external tools needed.
# ---------------------------------------------------------------
echo "=== Test 7: CPU Utilization vs Concurrency (10MB file) ==="

# CPU ticks per second
HZ=$(getconf CLK_TCK)

get_proc_cpu_ticks() {
    local pid=$1
    # fields 14+15 = utime+stime in ticks
    awk '{print $14+$15}' /proc/$pid/stat 2>/dev/null || echo 0
}

get_wall_ticks() {
    # wall clock in ticks: read /proc/uptime (seconds since boot)
    awk -v hz=$HZ '{printf "%.0f", $1*hz}' /proc/uptime
}

for c in 10 50 100 500 1000 5000 10000; do
    echo "Measuring CPU at concurrency: $c"

    SERVER_PID=$(pgrep -f fileserver_epoll)
    if [ -z "$SERVER_PID" ]; then
        echo "Error: Server not running"; continue
    fi

    if [ $c -le 1000 ]; then
        n_requests=$((c * 20))
        timeout=60
    elif [ $c -le 5000 ]; then
        n_requests=$((c * 20))
        timeout=120
    else
        n_requests=$((c * 10))
        timeout=180
    fi
    [ $n_requests -lt 20000 ] && n_requests=20000
    [ $n_requests -gt 50000 ] && n_requests=50000

    # Snapshot before
    cpu_before=$(get_proc_cpu_ticks $SERVER_PID)
    wall_before=$(get_wall_ticks)

    # Run benchmark (foreground so timing is accurate)
    ab -n $n_requests -c $c -s $timeout -k \
        -q http://localhost:8000/test_data/10mb.txt \
        >/dev/null 2>&1

    # Snapshot after
    cpu_after=$(get_proc_cpu_ticks $SERVER_PID)
    wall_after=$(get_wall_ticks)

    # Calculate: (cpu_ticks_used / wall_ticks_elapsed) * 100
    cpu_pct=$(awk -v cb=$cpu_before -v ca=$cpu_after \
                  -v wb=$wall_before -v wa=$wall_after \
              'BEGIN {
                  delta_cpu  = ca - cb
                  delta_wall = wa - wb
                  if (delta_wall > 0)
                      printf "%.1f", delta_cpu / delta_wall * 100
                  else
                      print "0"
              }')

    echo "  CPU: ${cpu_pct}%" | tee "${OUTPUT_DIR}/cpu_c${c}.txt"
    echo ""
done

echo "========================================"
echo "Benchmark Complete!"
echo "Results in ${OUTPUT_DIR}/"
echo "Run: python3 visualize_results_epoll_10MB.py to generate graphs"
echo "========================================"