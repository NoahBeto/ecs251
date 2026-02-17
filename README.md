# io_uring vs epoll performance test

The project test the throughput and latency of HTTP Server with io_uring or epoll. For convenience, I use liburing to build a server.

## Quick Start

### 1. install liburing

```bash
git submodule init
git submodule update
cd liburing
./configure --libdir=/usr/lib64 
make CFLAGS=-std=gnu99 && make install
```

### 2. build the test program

```bash
mkdir build
cd build
cmake ..
cmake --build .
```

### 3. run the program

```bash
./uring_server
# or
./epoll_server
# or
./build/fileserver_iouring
```
### 4. test the server

```bash
./test_server.sh
./quick_benchmark.sh
./syscall_analysis.sh
python visualize_iouring.py
```
