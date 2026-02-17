cmake_minimum_required(VERSION 3.16)
project(uring_server C)

set(CMAKE_C_STANDARD 11)

# liburing install path
set(LIBURING_INCLUDE_DIR "$ENV{HOME}/.local/include")
set(LIBURING_LIB_DIR "$ENV{HOME}/.local/lib64")

# io_uring file server
add_executable(fileserver_iouring fileserver_iouring.c fileserver.h)
target_include_directories(fileserver_iouring PRIVATE ${LIBURING_INCLUDE_DIR})
target_link_directories(fileserver_iouring PRIVATE ${LIBURING_LIB_DIR})
target_link_libraries(fileserver_iouring uring)
