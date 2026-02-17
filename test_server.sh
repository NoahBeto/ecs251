#!/bin/bash

#
# 1. fileserver_iouring is running at port 8000
# 2. chmod +x test_server.sh
# 3. ./test_server.sh

SERVER_PORT=8000
SERVER_URL="http://localhost:${SERVER_PORT}"
TEST_DIR="test_files"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

mkdir -p $TEST_DIR
cd $TEST_DIR

echo "========================================="
echo "io_uring File Server Test Suite"
echo "========================================="
echo ""

echo -e "${YELLOW}Creating test files...${NC}"
echo "Hello, io_uring!" > small.txt
dd if=/dev/urandom of=medium.bin bs=1K count=100 2>/dev/null
dd if=/dev/urandom of=large.bin bs=1M count=10 2>/dev/null
echo -e "${GREEN}✓ Test files created${NC}"
echo ""

echo -e "${YELLOW}Test 1: Basic GET request${NC}"
RESPONSE=$(curl -s ${SERVER_URL}/test_files/small.txt)
if [ "$RESPONSE" = "Hello, io_uring!" ]; then
    echo -e "${GREEN}✓ PASS: Basic GET works${NC}"
else
    echo -e "${RED}✗ FAIL: Basic GET failed${NC}"
fi
echo ""

echo -e "${YELLOW}Test 2: Range request (first 100 bytes)${NC}"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Range: bytes=0-99" ${SERVER_URL}/test_files/medium.bin)
if [ "$HTTP_CODE" = "206" ]; then
    echo -e "${GREEN}✓ PASS: Range request returns 206${NC}"
else
    echo -e "${RED}✗ FAIL: Expected 206, got ${HTTP_CODE}${NC}"
fi
echo ""

echo -e "${YELLOW}Test 3: Range request (last 500 bytes)${NC}"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Range: bytes=-500" ${SERVER_URL}/test_files/medium.bin)
if [ "$HTTP_CODE" = "206" ]; then
    echo -e "${GREEN}✓ PASS: Suffix range request works${NC}"
else
    echo -e "${RED}✗ FAIL: Expected 206, got ${HTTP_CODE}${NC}"
fi
echo ""

echo -e "${YELLOW}Test 4: Range request (from byte 1000 to end)${NC}"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Range: bytes=1000-" ${SERVER_URL}/test_files/medium.bin)
if [ "$HTTP_CODE" = "206" ]; then
    echo -e "${GREEN}✓ PASS: Open-ended range request works${NC}"
else
    echo -e "${RED}✗ FAIL: Expected 206, got ${HTTP_CODE}${NC}"
fi
echo ""

# echo -e "${YELLOW}Test 5: 404 Not Found${NC}"
# HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" ${SERVER_URL}/nonexistent.txt)
# if [ "$HTTP_CODE" = "404" ]; then
#     echo -e "${GREEN}✓ PASS: Returns 404 for missing files${NC}"
# else
#     echo -e "${RED}✗ FAIL: Expected 404, got ${HTTP_CODE}${NC}"
# fi
# echo ""

echo -e "${YELLOW}Test 5: File upload (POST)${NC}"
echo "Upload test content" > upload_source.txt
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST --data-binary @upload_source.txt ${SERVER_URL}/test_files/uploaded.txt)
if [ "$HTTP_CODE" = "201" ]; then
    echo -e "${GREEN}✓ PASS: Upload returns 201${NC}"
    sleep 1
    DOWNLOAD=$(curl -s ${SERVER_URL}/test_files/uploaded.txt)
    if [ "$DOWNLOAD" = "Upload test content" ]; then
        echo -e "${GREEN}✓ PASS: Uploaded file content matches${NC}"
    else
        echo -e "${RED}✗ FAIL: Uploaded content mismatch${NC}"
    fi
else
    echo -e "${RED}✗ FAIL: Expected 201, got ${HTTP_CODE}${NC}"
fi
echo ""

echo -e "${YELLOW}Test 6: Content-Type headers${NC}"
CONTENT_TYPE=$(curl -s -I ${SERVER_URL}/test_files/small.txt | grep -i "Content-Type:" | tr -d '\r')
if [[ "$CONTENT_TYPE" == *"text/plain"* ]]; then
    echo -e "${GREEN}✓ PASS: Correct Content-Type for .txt${NC}"
else
    echo -e "${RED}✗ FAIL: Wrong Content-Type: ${CONTENT_TYPE}${NC}"
fi
echo ""

echo -e "${YELLOW}Test 7: Accept-Ranges header${NC}"
ACCEPT_RANGES=$(curl -s -I ${SERVER_URL}/test_files/small.txt | grep -i "Accept-Ranges:" | tr -d '\r')
if [[ "$ACCEPT_RANGES" == *"bytes"* ]]; then
    echo -e "${GREEN}✓ PASS: Accept-Ranges header present${NC}"
else
    echo -e "${RED}✗ FAIL: Accept-Ranges header missing${NC}"
fi
echo ""

if command -v ab &> /dev/null; then
    echo -e "${YELLOW}Test 9: Performance benchmark${NC}"
    echo "Running: 1000 requests, 10 concurrent..."
    ab -n 1000 -c 10 -q ${SERVER_URL}/test_files/small.txt 2>&1 | grep "Requests per second"
    echo ""
else
    echo -e "${YELLOW}Apache Bench (ab) not installed, skipping performance test${NC}"
    echo ""
fi

echo "========================================="
echo "Test suite completed"
echo "========================================="

cd ..
exit 0