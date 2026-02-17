/*
  Extended static file server with io_uring support
  Supports: HTTP GET, Range Requests, File Uploads
*/

#ifndef URING_SERVER_FILESERVER_H
#define URING_SERVER_FILESERVER_H

#include <stdio.h>
#include <netinet/in.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/utsname.h>
#include <liburing.h>
#include <sys/epoll.h>
#include <errno.h>
#include <time.h>
#include <linux/stat.h>

#ifndef STATX_SIZE
#define STATX_SIZE 0x00000200U
#endif

#define SERVER_STRING           "Server: StaticFileServer/1.0\r\n"
#define DEFAULT_SERVER_PORT     8000
#define QUEUE_DEPTH             256
#define READ_SZ                 8192
#define FILE_CHUNK_SIZE         (64 * 1024)  // 64KB chunks for file reading

// Event types
#define EVENT_TYPE_ACCEPT       0
#define EVENT_TYPE_READ         1
#define EVENT_TYPE_WRITE        2
#define EVENT_TYPE_OPEN         3
#define EVENT_TYPE_FILE_READ    4
#define EVENT_TYPE_STAT         5
#define EVENT_TYPE_FILE_WRITE   6
#define EVENT_TYPE_CLOSE        7

#define MIN_KERNEL_VERSION      5
#define MIN_MAJOR_VERSION       5

#define MAX_EVENTS 100
#define MAX_PATH_LEN 512
#define MAX_UPLOAD_SIZE (100 * 1024 * 1024)  // 100MB max upload

// HTTP Response templates
#define HTTP_200 "HTTP/1.1 200 OK\r\n"
#define HTTP_206 "HTTP/1.1 206 Partial Content\r\n"
#define HTTP_400 "HTTP/1.1 400 Bad Request\r\n"
#define HTTP_404 "HTTP/1.1 404 Not Found\r\n"
#define HTTP_416 "HTTP/1.1 416 Range Not Satisfiable\r\n"
#define HTTP_201 "HTTP/1.1 201 Created\r\n"
#define HTTP_500 "HTTP/1.1 500 Internal Server Error\r\n"

#define UNIMPLEMENT "HTTP/1.1 400 Bad Request\r\n"\
                    "Content-Type: text/html\r\n"\
                    "Content-Length: 197\r\n"\
                    "\r\n"\
                    "<html>"\
                    "<head><title>Bad Request</title></head>"\
                    "<body>"\
                    "<h1>400 Bad Request</h1>"\
                    "<p>Unimplemented method.</p>"\
                    "</body>"\
                    "</html>"

#define ERRORMSG_404 "HTTP/1.1 404 Not Found\r\n"\
                     "Content-Type: text/html\r\n"\
                     "Content-Length: 185\r\n"\
                     "\r\n"\
                     "<html>"\
                     "<head><title>Not Found</title></head>"\
                     "<body>"\
                     "<h1>404 Not Found</h1>"\
                     "<p>File not found.</p>"\
                     "</body>"\
                     "</html>"

#define ERRORMSG_416 "HTTP/1.1 416 Range Not Satisfiable\r\n"\
                     "Content-Type: text/html\r\n"\
                     "Content-Length: 200\r\n"\
                     "\r\n"\
                     "<html>"\
                     "<head><title>Range Error</title></head>"\
                     "<body>"\
                     "<h1>416 Range Not Satisfiable</h1>"\
                     "</body>"\
                     "</html>"

// Request structure with file handling support
struct request {
    int event_type;
    int iovec_count;
    int client_socket;
    int file_fd;
    
    // File information
    char filepath[MAX_PATH_LEN];
    off_t file_size;
    off_t file_offset;
    off_t bytes_to_read;
    off_t bytes_read;
    
    // Range request support
    int is_range_request;
    off_t range_start;
    off_t range_end;
    
    // Upload support
    int is_upload;
    off_t upload_size;
    off_t upload_received;
    char *upload_buffer;
    
    // HTTP request parsing
    char method[16];
    char *request_buffer;
    
    struct iovec iov[];
};

struct file_stat_data {
    struct request *req;
    struct stat st;
};

// Core functions
void fatal_error(const char *syscall);
void *zh_malloc(size_t size);
int setup_listening_socket(int port);

// io_uring operations
int add_accept_request(int server_socket, struct sockaddr_in *client_addr,
                       socklen_t *client_addr_len);
int add_read_request(int client_socket);
int add_write_request(struct request *req);
int add_statx_request(struct request *req);
int add_open_request(struct request *req, int flags, mode_t mode);
int add_file_read_request(struct request *req);
int add_file_write_request(struct request *req, const char *data, size_t len);
int add_close_request(struct request *req);

// HTTP handling
void handle_client_request(struct request *req);
void handle_get_method(struct request *req);
void handle_post_method(struct request *req);
void handle_unimplemented_method(struct request *req);
void handle_http_404(struct request *req);
void handle_range_error(struct request *req);

// HTTP parsing
int parse_http_request(struct request *req, const char *buffer, size_t len);
int parse_range_header(const char *range_header, off_t *start, off_t *end, off_t file_size);
const char *get_content_type(const char *path);

// Response generation
void send_response_headers(struct request *req, int status_code);
void send_static_response(struct request *req, const char *response);

// Utility functions
void strtolower(char *str);
const char *get_filename_ext(const char *filename);
char *get_date_string(void);

#endif // URING_SERVER_FILESERVER_H