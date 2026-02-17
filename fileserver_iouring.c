/*
  Static File Server with io_uring
  Supports: GET requests, Range requests, File uploads (POST/PUT)
*/

#include "fileserver.h"

struct io_uring ring;

void fatal_error(const char *syscall) {
    perror(syscall);
    exit(EXIT_FAILURE);
}

void *zh_malloc(size_t size) {
    void *ptr = malloc(size);
    if (!ptr) {
        fatal_error("malloc");
    }
    memset(ptr, 0, size);
    return ptr;
}

int check_kernel_version() {
    struct utsname buffer;
    char *p;
    long ver[16];
    int i = 0;

    if (uname(&buffer) != 0) {
        perror("uname");
        exit(EXIT_FAILURE);
    }

    p = buffer.release;
    while (*p) {
        if (isdigit(*p)) {
            ver[i] = strtol(p, &p, 10);
            i++;
        } else {
            p++;
        }
    }
    
    printf("Minimum kernel version required: %d.%d\n",
           MIN_KERNEL_VERSION, MIN_MAJOR_VERSION);
    if (ver[0] >= MIN_KERNEL_VERSION && ver[1] >= MIN_MAJOR_VERSION) {
        printf("Your kernel version: %ld.%ld\n", ver[0], ver[1]);
        return 0;
    }
    fprintf(stderr, "Error: kernel version %ld.%ld is too old\n", ver[0], ver[1]);
    return 1;
}

int setup_listening_socket(int port) {
    int sock;
    struct sockaddr_in srv_addr;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
        fatal_error("socket");

    int enable = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
        fatal_error("setsockopt(SO_REUSEADDR)");

    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(port);
    srv_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (const struct sockaddr *)&srv_addr, sizeof(srv_addr)) < 0)
        fatal_error("bind");

    if (listen(sock, 128) < 0)
        fatal_error("listen");

    return sock;
}

// ===== io_uring Operations =====

int add_accept_request(int server_socket, struct sockaddr_in *client_addr,
                       socklen_t *client_addr_len) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    io_uring_prep_accept(sqe, server_socket, (struct sockaddr *)client_addr,
                         client_addr_len, 0);
    
    struct request *req = zh_malloc(sizeof(*req));
    req->event_type = EVENT_TYPE_ACCEPT;
    io_uring_sqe_set_data(sqe, req);
    io_uring_submit(&ring);
    return 0;
}

int add_read_request(int client_socket) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    struct request *req = zh_malloc(sizeof(*req) + sizeof(struct iovec));
    
    req->iov[0].iov_base = zh_malloc(READ_SZ);
    req->iov[0].iov_len = READ_SZ;
    req->iovec_count = 1;
    req->event_type = EVENT_TYPE_READ;
    req->client_socket = client_socket;
    req->file_fd = -1;
    
    io_uring_prep_readv(sqe, client_socket, &req->iov[0], 1, 0);
    io_uring_sqe_set_data(sqe, req);
    io_uring_submit(&ring);
    return 0;
}

int add_write_request(struct request *req) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    req->event_type = EVENT_TYPE_WRITE;
    io_uring_prep_writev(sqe, req->client_socket, req->iov, req->iovec_count, 0);
    io_uring_sqe_set_data(sqe, req);
    io_uring_submit(&ring);
    return 0;
}

int add_statx_request(struct request *req) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    struct file_stat_data *stat_data = zh_malloc(sizeof(struct file_stat_data));
    
    stat_data->req = req;
    req->event_type = EVENT_TYPE_OPEN;  // First open, then stat
    
    // Open file first to get fd for fstat
    io_uring_prep_openat(sqe, AT_FDCWD, req->filepath, O_RDONLY, 0);
    io_uring_sqe_set_data(sqe, req);
    io_uring_submit(&ring);
    return 0;
}

int add_open_request(struct request *req, int flags, mode_t mode) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    req->event_type = EVENT_TYPE_OPEN;
    
    io_uring_prep_openat(sqe, AT_FDCWD, req->filepath, flags, mode);
    io_uring_sqe_set_data(sqe, req);
    io_uring_submit(&ring);
    return 0;
}

int add_file_read_request(struct request *req) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    
    // Calculate chunk size for this read
    size_t remaining = req->bytes_to_read - req->bytes_read;
    size_t chunk_size = remaining < FILE_CHUNK_SIZE ? remaining : FILE_CHUNK_SIZE;
    
    // Create new request with buffer embedded
    struct request *read_req = zh_malloc(sizeof(*read_req) + sizeof(struct iovec));
    
    // Copy relevant fields
    read_req->event_type = EVENT_TYPE_FILE_READ;
    read_req->client_socket = req->client_socket;
    read_req->file_fd = req->file_fd;
    read_req->file_offset = req->file_offset;
    read_req->bytes_to_read = req->bytes_to_read;
    read_req->bytes_read = req->bytes_read;
    
    // Allocate and attach buffer
    read_req->iov[0].iov_base = zh_malloc(chunk_size);
    read_req->iov[0].iov_len = chunk_size;
    
    io_uring_prep_read(sqe, req->file_fd, read_req->iov[0].iov_base, 
                       chunk_size, req->file_offset);
    io_uring_sqe_set_data(sqe, read_req);
    io_uring_submit(&ring);
    return 0;
}

int add_file_write_request(struct request *req, const char *data, size_t len) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    req->event_type = EVENT_TYPE_FILE_WRITE;
    
    io_uring_prep_write(sqe, req->file_fd, data, len, req->file_offset);
    io_uring_sqe_set_data(sqe, req);
    io_uring_submit(&ring);
    return 0;
}

int add_close_request(struct request *req) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    req->event_type = EVENT_TYPE_CLOSE;
    
    io_uring_prep_close(sqe, req->file_fd);
    io_uring_sqe_set_data(sqe, req);
    io_uring_submit(&ring);
    return 0;
}

// ===== Utility Functions =====

void strtolower(char *str) {
    for (; *str; str++)
        *str = tolower(*str);
}

const char *get_filename_ext(const char *filename) {
    const char *dot = strrchr(filename, '.');
    if (!dot || dot == filename) return "";
    return dot + 1;
}

const char *get_content_type(const char *path) {
    const char *ext = get_filename_ext(path);
    
    if (strcasecmp(ext, "html") == 0 || strcasecmp(ext, "htm") == 0)
        return "text/html";
    else if (strcasecmp(ext, "txt") == 0)
        return "text/plain";
    else if (strcasecmp(ext, "css") == 0)
        return "text/css";
    else if (strcasecmp(ext, "js") == 0)
        return "application/javascript";
    else if (strcasecmp(ext, "json") == 0)
        return "application/json";
    else if (strcasecmp(ext, "jpg") == 0 || strcasecmp(ext, "jpeg") == 0)
        return "image/jpeg";
    else if (strcasecmp(ext, "png") == 0)
        return "image/png";
    else if (strcasecmp(ext, "gif") == 0)
        return "image/gif";
    else if (strcasecmp(ext, "pdf") == 0)
        return "application/pdf";
    else
        return "application/octet-stream";
}

char *get_date_string(void) {
    static char buf[128];
    time_t now = time(NULL);
    struct tm *tm = gmtime(&now);
    strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S GMT", tm);
    return buf;
}

// ===== HTTP Parsing =====

int parse_http_request(struct request *req, const char *buffer, size_t len) {
    char *line_end;
    char *method_end;
    char *path_start;
    char *path_end;
    
    // Save request buffer for later parsing
    req->request_buffer = strndup(buffer, len);
    
    // Find first line end
    line_end = strstr(req->request_buffer, "\r\n");
    if (!line_end) {
        return -1;
    }
    
    // Parse method
    method_end = strchr(req->request_buffer, ' ');
    if (!method_end || method_end > line_end) {
        return -1;
    }
    
    size_t method_len = method_end - req->request_buffer;
    if (method_len >= sizeof(req->method)) {
        return -1;
    }
    
    strncpy(req->method, req->request_buffer, method_len);
    req->method[method_len] = '\0';
    strtolower(req->method);
    
    // Parse path
    path_start = method_end + 1;
    path_end = strchr(path_start, ' ');
    if (!path_end || path_end > line_end) {
        return -1;
    }
    
    size_t path_len = path_end - path_start;
    if (path_len >= MAX_PATH_LEN - 1) {
        return -1;
    }
    
    // Construct filepath - remove leading / and don't add ./
    if (*path_start == '/') {
        path_start++;
        path_len--;
    }
    
    strncpy(req->filepath, path_start, path_len);
    req->filepath[path_len] = '\0';
    
    // Handle root path
    if (req->filepath[0] == '\0' || strcmp(req->filepath, "") == 0) {
        strcpy(req->filepath, "index.html");
    }
    
    // Check for Range header
    char *range_header = strstr(req->request_buffer, "Range: bytes=");
    if (range_header) {
        req->is_range_request = 1;
        range_header += 13;  // Skip "Range: bytes="
        char *range_end = strstr(range_header, "\r\n");
        if (range_end) {
            *range_end = '\0';
            // Will parse actual values after we know file size
        }
    }
    
    // Check for Content-Length (upload)
    char *content_len = strstr(req->request_buffer, "Content-Length: ");
    if (content_len) {
        content_len += 16;
        req->upload_size = atoll(content_len);
    }
    
    return 0;
}

int parse_range_header(const char *range_header, off_t *start, off_t *end, off_t file_size) {
    // Format: "Range: bytes=start-end" or "Range: bytes=start-" or "Range: bytes=-suffix"
    const char *bytes_pos = strstr(range_header, "bytes=");
    if (!bytes_pos) {
        return -1;
    }
    bytes_pos += 6;
    
    if (*bytes_pos == '-') {
        // Suffix range: -500 means last 500 bytes
        long suffix = atol(bytes_pos + 1);
        *start = file_size - suffix;
        *end = file_size - 1;
    } else {
        *start = atoll(bytes_pos);
        const char *dash = strchr(bytes_pos, '-');
        if (!dash) {
            return -1;
        }
        
        if (*(dash + 1) == '\0' || *(dash + 1) == '\r') {
            // Open-ended: 500- means from byte 500 to end
            *end = file_size - 1;
        } else {
            *end = atoll(dash + 1);
        }
    }
    
    // Validate range
    if (*start < 0 || *end >= file_size || *start > *end) {
        return -1;
    }
    
    return 0;
}

// ===== Response Generation =====

void send_static_response(struct request *req, const char *response) {
    size_t len = strlen(response);
    
    struct request *write_req = zh_malloc(sizeof(*write_req) + sizeof(struct iovec));
    write_req->client_socket = req->client_socket;
    write_req->iovec_count = 1;
    write_req->iov[0].iov_base = strdup(response);
    write_req->iov[0].iov_len = len;
    write_req->file_fd = -1;
    write_req->bytes_to_read = 0;
    write_req->bytes_read = 0;
    
    add_write_request(write_req);
    
    // Clean up original request
    // Only free iov_base if it was actually allocated (from READ event)
    if (req->iovec_count > 0 && req->iov[0].iov_base) {
        free(req->iov[0].iov_base);
    }
    if (req->request_buffer) {
        free(req->request_buffer);
    }
    if (req->upload_buffer) {
        free(req->upload_buffer);
    }
    free(req);
}

void send_response_headers(struct request *req, int status_code) {
    char header[2048];
    const char *status_line;
    
    switch (status_code) {
        case 200: status_line = HTTP_200; break;
        case 206: status_line = HTTP_206; break;
        case 201: status_line = HTTP_201; break;
        case 404: status_line = HTTP_404; break;
        case 416: status_line = HTTP_416; break;
        default:  status_line = HTTP_500; break;
    }
    
    int header_len;
    if (status_code == 206) {
        // Partial content response
        header_len = snprintf(header, sizeof(header),
            "%s"
            "Content-Type: %s\r\n"
            "Content-Length: %ld\r\n"
            "Content-Range: bytes %ld-%ld/%ld\r\n"
            "Accept-Ranges: bytes\r\n"
            "Date: %s\r\n"
            "%s\r\n",
            status_line,
            get_content_type(req->filepath),
            req->bytes_to_read,
            req->range_start,
            req->range_end,
            req->file_size,
            get_date_string(),
            SERVER_STRING);
    } else if (status_code == 200 && req->file_size > 0) {
        // Full file response
        header_len = snprintf(header, sizeof(header),
            "%s"
            "Content-Type: %s\r\n"
            "Content-Length: %ld\r\n"
            "Accept-Ranges: bytes\r\n"
            "Date: %s\r\n"
            "%s\r\n",
            status_line,
            get_content_type(req->filepath),
            req->file_size,
            get_date_string(),
            SERVER_STRING);
    } else if (status_code == 201) {
        // Upload success
        header_len = snprintf(header, sizeof(header),
            "%s"
            "Content-Length: 0\r\n"
            "Date: %s\r\n"
            "%s\r\n",
            status_line,
            get_date_string(),
            SERVER_STRING);
    } else {
        // Error response
        header_len = snprintf(header, sizeof(header),
            "%s"
            "Content-Type: text/html\r\n"
            "Date: %s\r\n"
            "%s\r\n",
            status_line,
            get_date_string(),
            SERVER_STRING);
    }
    
    // Allocate new write request for headers
    struct request *write_req = zh_malloc(sizeof(*write_req) + sizeof(struct iovec));
    write_req->client_socket = req->client_socket;
    write_req->iovec_count = 1;
    write_req->iov[0].iov_base = strndup(header, header_len);
    write_req->iov[0].iov_len = header_len;
    write_req->file_fd = req->file_fd;  // Keep file fd for later reads
    
    // Copy request info for subsequent file reads
    memcpy(write_req->filepath, req->filepath, MAX_PATH_LEN);
    write_req->file_size = req->file_size;
    write_req->file_offset = req->file_offset;
    write_req->bytes_to_read = req->bytes_to_read;
    write_req->bytes_read = 0;
    write_req->is_upload = req->is_upload;
    
    add_write_request(write_req);
}

// ===== HTTP Handlers =====

void handle_http_404(struct request *req) {
    send_static_response(req, ERRORMSG_404);
    // Don't free here - already freed in send_static_response path
}

void handle_range_error(struct request *req) {
    send_static_response(req, ERRORMSG_416);
}

void handle_unimplemented_method(struct request *req) {
    send_static_response(req, UNIMPLEMENT);
}

void handle_get_method(struct request *req) {
    // Open file directly - we'll get size with fstat after opening
    add_open_request(req, O_RDONLY, 0);
}

void handle_post_method(struct request *req) {
    // POST data is in the request body after headers
    // Find the end of headers (blank line)
    char *body_start = strstr((char *)req->iov[0].iov_base, "\r\n\r\n");
    if (!body_start) {
        send_static_response(req, UNIMPLEMENT);
        return;
    }
    body_start += 4; // Skip past "\r\n\r\n"
    
    // Calculate body size
    char *buffer_start = (char *)req->iov[0].iov_base;
    size_t headers_len = body_start - buffer_start;
    size_t total_read = req->iov[0].iov_len;
    
    if (total_read <= headers_len) {
        send_static_response(req, UNIMPLEMENT);
        return;
    }
    
    size_t body_len = total_read - headers_len;
    
    if (body_len == 0 || body_len > MAX_UPLOAD_SIZE) {
        send_static_response(req, UNIMPLEMENT);
        return;
    }
    
    // Store upload data
    req->upload_buffer = malloc(body_len);
    memcpy(req->upload_buffer, body_start, body_len);
    req->upload_size = body_len;
    req->upload_received = body_len;
    req->is_upload = 1;
    
    printf("Upload: %zu bytes\n", body_len);
    
    // Open file for writing
    add_open_request(req, O_WRONLY | O_CREAT | O_TRUNC, 0644);
}

void handle_client_request(struct request *req) {
    // Parse HTTP request
    if (parse_http_request(req, req->iov[0].iov_base, req->iov[0].iov_len) < 0) {
        send_static_response(req, UNIMPLEMENT);
        return;
    }
    
    printf("Request: %s %s\n", req->method, req->filepath);
    
    if (strcmp(req->method, "get") == 0 || strcmp(req->method, "head") == 0) {
        handle_get_method(req);
    } else if (strcmp(req->method, "post") == 0 || strcmp(req->method, "put") == 0) {
        handle_post_method(req);
    } else {
        handle_unimplemented_method(req);
    }
}

// ===== Main Event Loop =====

void server_loop_uring(int server_socket) {
    struct io_uring_cqe *cqe;
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    add_accept_request(server_socket, &client_addr, &client_addr_len);

    while (1) {
        int ret = io_uring_wait_cqe(&ring, &cqe);
        if (ret < 0) {
            fatal_error("io_uring_wait_cqe");
        }

        void *user_data = io_uring_cqe_get_data(cqe);
        
        if (cqe->res < 0 && user_data) {
            struct request *req = (struct request *)user_data;
            fprintf(stderr, "Async operation failed: %s (event: %d)\n",
                    strerror(-cqe->res), req->event_type);
            
            // Clean up on error
            if (req->file_fd >= 0) {
                close(req->file_fd);
            }
            if (req->client_socket >= 0) {
                close(req->client_socket);
            }
            free(req);
            io_uring_cqe_seen(&ring, cqe);
            continue;
        }

        // Determine event type and handle
        struct request *req = (struct request *)user_data;
        
        switch (req->event_type) {
            case EVENT_TYPE_ACCEPT: {
                int client_fd = cqe->res;
                add_accept_request(server_socket, &client_addr, &client_addr_len);
                add_read_request(client_fd);
                free(req);
                break;
            }
            
            case EVENT_TYPE_READ: {
                if (cqe->res == 0) {
                    // Connection closed
                    close(req->client_socket);
                    free(req->iov[0].iov_base);
                    free(req);
                    break;
                }
                
                handle_client_request(req);
                // Don't free req or buffer yet - used in subsequent operations
                break;
            }
            
            case EVENT_TYPE_OPEN: {
                int fd = cqe->res;
                if (fd < 0) {
                    // File not found - send 404
                    // send_static_response will free everything
                    send_static_response(req, ERRORMSG_404);
                    break;
                }
                
                req->file_fd = fd;
                
                if (req->is_upload) {
                    // Write uploaded data to file
                    if (req->upload_buffer && req->upload_size > 0) {
                        ssize_t written = write(req->file_fd, req->upload_buffer, req->upload_size);
                        if (written < 0) {
                            close(req->file_fd);
                            if (req->upload_buffer) free(req->upload_buffer);
                            send_static_response(req, "HTTP/1.1 500 Internal Server Error\r\n\r\n");
                            break;
                        }
                    }
                    close(req->file_fd);
                    
                    // Send success response
                    struct request *write_req = zh_malloc(sizeof(*write_req) + sizeof(struct iovec));
                    write_req->client_socket = req->client_socket;
                    write_req->iovec_count = 1;
                    write_req->file_fd = -1;
                    char *response = "HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n";
                    write_req->iov[0].iov_base = strdup(response);
                    write_req->iov[0].iov_len = strlen(response);
                    add_write_request(write_req);
                    
                    if (req->request_buffer) free(req->request_buffer);
                    if (req->upload_buffer) free(req->upload_buffer);
                    if (req->iov[0].iov_base) free(req->iov[0].iov_base);
                    free(req);
                } else {
                    // Get file size using fstat
                    struct stat st;
                    if (fstat(req->file_fd, &st) < 0) {
                        close(req->file_fd);
                        send_static_response(req, ERRORMSG_404);
                        break;
                    }
                    
                    req->file_size = st.st_size;
                    
                    // Parse range if present
                    if (req->is_range_request) {
                        char *range_header = strstr(req->request_buffer, "Range: ");
                        if (range_header && parse_range_header(range_header, &req->range_start, 
                                                               &req->range_end, req->file_size) == 0) {
                            req->file_offset = req->range_start;
                            req->bytes_to_read = req->range_end - req->range_start + 1;
                        } else {
                            close(req->file_fd);
                            send_static_response(req, ERRORMSG_416);
                            break;
                        }
                    } else {
                        req->file_offset = 0;
                        req->bytes_to_read = req->file_size;
                        req->range_start = 0;
                        req->range_end = req->file_size - 1;
                    }
                    
                    // Send headers and prepare for file reading
                    send_response_headers(req, req->is_range_request ? 206 : 200);
                    if (req->request_buffer) free(req->request_buffer);
                    if (req->iov[0].iov_base) free(req->iov[0].iov_base);
                    free(req);
                }
                break;
            }
            
            case EVENT_TYPE_WRITE: {
                // After headers are written, start reading file if needed
                if (req->file_fd >= 0 && req->bytes_read < req->bytes_to_read) {
                    add_file_read_request(req);
                } else {
                    // All done - close connection
                    for (int i = 0; i < req->iovec_count; i++) {
                        free(req->iov[i].iov_base);
                    }
                    if (req->file_fd >= 0) {
                        close(req->file_fd);
                    }
                    if (req->client_socket >= 0) {
                        close(req->client_socket);
                    }
                    free(req);
                }
                break;
            }
            
            case EVENT_TYPE_FILE_READ: {
                size_t bytes_read = cqe->res;
                
                if (bytes_read <= 0) {
                    // Error or EOF
                    free(req->iov[0].iov_base);
                    if (req->file_fd >= 0) close(req->file_fd);
                    close(req->client_socket);
                    free(req);
                    break;
                }
                
                // Create write request with the data we just read
                struct request *write_req = zh_malloc(sizeof(*write_req) + sizeof(struct iovec));
                write_req->event_type = EVENT_TYPE_WRITE;
                write_req->client_socket = req->client_socket;
                write_req->file_fd = req->file_fd;
                write_req->iovec_count = 1;
                
                // Transfer buffer ownership to write request
                write_req->iov[0].iov_base = req->iov[0].iov_base;
                write_req->iov[0].iov_len = bytes_read;
                
                // Update progress tracking
                write_req->bytes_read = req->bytes_read + bytes_read;
                write_req->bytes_to_read = req->bytes_to_read;
                write_req->file_offset = req->file_offset + bytes_read;
                
                add_write_request(write_req);
                
                // Free the read request (buffer ownership transferred)
                free(req);
                break;
            }
            
            case EVENT_TYPE_CLOSE: {
                free(req);
                break;
            }
            
            default:
                fprintf(stderr, "Unknown event type: %d\n", req->event_type);
                free(req);
                break;
        }

        io_uring_cqe_seen(&ring, cqe);
    }
}

void sigint_handler(int signo) {
    printf("\n^C pressed. Shutting down.\n");
    io_uring_queue_exit(&ring);
    exit(0);
}

int main(int argc, char *argv[]) {
    int port = DEFAULT_SERVER_PORT;
    
    if (argc > 1) {
        port = atoi(argv[1]);
    }
    
    if (check_kernel_version()) {
        return EXIT_FAILURE;
    }

    int server_socket = setup_listening_socket(port);
    printf("Static File Server listening on port %d\n", port);
    printf("Document root: current directory\n");
    printf("Supported: GET (with Range), POST/PUT (upload)\n\n");

    signal(SIGINT, sigint_handler);
    
    if (io_uring_queue_init(QUEUE_DEPTH, &ring, 0) < 0) {
        fatal_error("io_uring_queue_init");
    }
    
    server_loop_uring(server_socket);

    return 0;
}


// /*
//   Static File Server with io_uring
//   Supports: GET requests, Range requests, File uploads (POST/PUT)
// */

// #include "fileserver.h"

// struct io_uring ring;

// void fatal_error(const char *syscall) {
//     perror(syscall);
//     exit(EXIT_FAILURE);
// }

// void *zh_malloc(size_t size) {
//     void *ptr = malloc(size);
//     if (!ptr) {
//         fatal_error("malloc");
//     }
//     memset(ptr, 0, size);
//     return ptr;
// }

// int check_kernel_version() {
//     struct utsname buffer;
//     char *p;
//     long ver[16];
//     int i = 0;

//     if (uname(&buffer) != 0) {
//         perror("uname");
//         exit(EXIT_FAILURE);
//     }

//     p = buffer.release;
//     while (*p) {
//         if (isdigit(*p)) {
//             ver[i] = strtol(p, &p, 10);
//             i++;
//         } else {
//             p++;
//         }
//     }
    
//     printf("Minimum kernel version required: %d.%d\n",
//            MIN_KERNEL_VERSION, MIN_MAJOR_VERSION);
//     if (ver[0] >= MIN_KERNEL_VERSION && ver[1] >= MIN_MAJOR_VERSION) {
//         printf("Your kernel version: %ld.%ld\n", ver[0], ver[1]);
//         return 0;
//     }
//     fprintf(stderr, "Error: kernel version %ld.%ld is too old\n", ver[0], ver[1]);
//     return 1;
// }

// int setup_listening_socket(int port) {
//     int sock;
//     struct sockaddr_in srv_addr;

//     sock = socket(AF_INET, SOCK_STREAM, 0);
//     if (sock < 0)
//         fatal_error("socket");

//     int enable = 1;
//     if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
//         fatal_error("setsockopt(SO_REUSEADDR)");

//     memset(&srv_addr, 0, sizeof(srv_addr));
//     srv_addr.sin_family = AF_INET;
//     srv_addr.sin_port = htons(port);
//     srv_addr.sin_addr.s_addr = INADDR_ANY;

//     if (bind(sock, (const struct sockaddr *)&srv_addr, sizeof(srv_addr)) < 0)
//         fatal_error("bind");

//     if (listen(sock, 128) < 0)
//         fatal_error("listen");

//     return sock;
// }

// // ===== io_uring Operations =====

// int add_accept_request(int server_socket, struct sockaddr_in *client_addr,
//                        socklen_t *client_addr_len) {
//     struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
//     io_uring_prep_accept(sqe, server_socket, (struct sockaddr *)client_addr,
//                          client_addr_len, 0);
    
//     struct request *req = zh_malloc(sizeof(*req));
//     req->event_type = EVENT_TYPE_ACCEPT;
//     io_uring_sqe_set_data(sqe, req);
//     io_uring_submit(&ring);
//     return 0;
// }

// int add_read_request(int client_socket) {
//     struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
//     struct request *req = zh_malloc(sizeof(*req) + sizeof(struct iovec));
    
//     req->iov[0].iov_base = zh_malloc(READ_SZ);
//     req->iov[0].iov_len = READ_SZ;
//     req->event_type = EVENT_TYPE_READ;
//     req->client_socket = client_socket;
//     req->file_fd = -1;
    
//     io_uring_prep_readv(sqe, client_socket, &req->iov[0], 1, 0);
//     io_uring_sqe_set_data(sqe, req);
//     io_uring_submit(&ring);
//     return 0;
// }

// int add_write_request(struct request *req) {
//     struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
//     req->event_type = EVENT_TYPE_WRITE;
//     io_uring_prep_writev(sqe, req->client_socket, req->iov, req->iovec_count, 0);
//     io_uring_sqe_set_data(sqe, req);
//     io_uring_submit(&ring);
//     return 0;
// }

// int add_statx_request(struct request *req) {
//     struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
//     struct file_stat_data *stat_data = zh_malloc(sizeof(struct file_stat_data));
    
//     stat_data->req = req;
//     req->event_type = EVENT_TYPE_OPEN;  // First open, then stat
    
//     // Open file first to get fd for fstat
//     io_uring_prep_openat(sqe, AT_FDCWD, req->filepath, O_RDONLY, 0);
//     io_uring_sqe_set_data(sqe, req);
//     io_uring_submit(&ring);
//     return 0;
// }

// int add_open_request(struct request *req, int flags, mode_t mode) {
//     struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
//     req->event_type = EVENT_TYPE_OPEN;
    
//     io_uring_prep_openat(sqe, AT_FDCWD, req->filepath, flags, mode);
//     io_uring_sqe_set_data(sqe, req);
//     io_uring_submit(&ring);
//     return 0;
// }

// int add_file_read_request(struct request *req) {
//     struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    
//     // Calculate chunk size for this read
//     size_t remaining = req->bytes_to_read - req->bytes_read;
//     size_t chunk_size = remaining < FILE_CHUNK_SIZE ? remaining : FILE_CHUNK_SIZE;
    
//     // Create new request with buffer embedded
//     struct request *read_req = zh_malloc(sizeof(*read_req) + sizeof(struct iovec));
    
//     // Copy relevant fields
//     read_req->event_type = EVENT_TYPE_FILE_READ;
//     read_req->client_socket = req->client_socket;
//     read_req->file_fd = req->file_fd;
//     read_req->file_offset = req->file_offset;
//     read_req->bytes_to_read = req->bytes_to_read;
//     read_req->bytes_read = req->bytes_read;
    
//     // Allocate and attach buffer
//     read_req->iov[0].iov_base = zh_malloc(chunk_size);
//     read_req->iov[0].iov_len = chunk_size;
    
//     io_uring_prep_read(sqe, req->file_fd, read_req->iov[0].iov_base, 
//                        chunk_size, req->file_offset);
//     io_uring_sqe_set_data(sqe, read_req);
//     io_uring_submit(&ring);
//     return 0;
// }

// int add_file_write_request(struct request *req, const char *data, size_t len) {
//     struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
//     req->event_type = EVENT_TYPE_FILE_WRITE;
    
//     io_uring_prep_write(sqe, req->file_fd, data, len, req->file_offset);
//     io_uring_sqe_set_data(sqe, req);
//     io_uring_submit(&ring);
//     return 0;
// }

// int add_close_request(struct request *req) {
//     struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
//     req->event_type = EVENT_TYPE_CLOSE;
    
//     io_uring_prep_close(sqe, req->file_fd);
//     io_uring_sqe_set_data(sqe, req);
//     io_uring_submit(&ring);
//     return 0;
// }

// // ===== Utility Functions =====

// void strtolower(char *str) {
//     for (; *str; str++)
//         *str = tolower(*str);
// }

// const char *get_filename_ext(const char *filename) {
//     const char *dot = strrchr(filename, '.');
//     if (!dot || dot == filename) return "";
//     return dot + 1;
// }

// const char *get_content_type(const char *path) {
//     const char *ext = get_filename_ext(path);
    
//     if (strcasecmp(ext, "html") == 0 || strcasecmp(ext, "htm") == 0)
//         return "text/html";
//     else if (strcasecmp(ext, "txt") == 0)
//         return "text/plain";
//     else if (strcasecmp(ext, "css") == 0)
//         return "text/css";
//     else if (strcasecmp(ext, "js") == 0)
//         return "application/javascript";
//     else if (strcasecmp(ext, "json") == 0)
//         return "application/json";
//     else if (strcasecmp(ext, "jpg") == 0 || strcasecmp(ext, "jpeg") == 0)
//         return "image/jpeg";
//     else if (strcasecmp(ext, "png") == 0)
//         return "image/png";
//     else if (strcasecmp(ext, "gif") == 0)
//         return "image/gif";
//     else if (strcasecmp(ext, "pdf") == 0)
//         return "application/pdf";
//     else
//         return "application/octet-stream";
// }

// char *get_date_string(void) {
//     static char buf[128];
//     time_t now = time(NULL);
//     struct tm *tm = gmtime(&now);
//     strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S GMT", tm);
//     return buf;
// }

// // ===== HTTP Parsing =====

// int parse_http_request(struct request *req, const char *buffer, size_t len) {
//     char *line_end;
//     char *method_end;
//     char *path_start;
//     char *path_end;
    
//     // Save request buffer for later parsing
//     req->request_buffer = strndup(buffer, len);
    
//     // Find first line end
//     line_end = strstr(req->request_buffer, "\r\n");
//     if (!line_end) {
//         return -1;
//     }
    
//     // Parse method
//     method_end = strchr(req->request_buffer, ' ');
//     if (!method_end || method_end > line_end) {
//         return -1;
//     }
    
//     size_t method_len = method_end - req->request_buffer;
//     if (method_len >= sizeof(req->method)) {
//         return -1;
//     }
    
//     strncpy(req->method, req->request_buffer, method_len);
//     req->method[method_len] = '\0';
//     strtolower(req->method);
    
//     // Parse path
//     path_start = method_end + 1;
//     path_end = strchr(path_start, ' ');
//     if (!path_end || path_end > line_end) {
//         return -1;
//     }
    
//     size_t path_len = path_end - path_start;
//     if (path_len >= MAX_PATH_LEN - 1) {
//         return -1;
//     }
    
//     // Construct filepath - remove leading / and don't add ./
//     if (*path_start == '/') {
//         path_start++;
//         path_len--;
//     }
    
//     strncpy(req->filepath, path_start, path_len);
//     req->filepath[path_len] = '\0';
    
//     // Handle root path
//     if (req->filepath[0] == '\0' || strcmp(req->filepath, "") == 0) {
//         strcpy(req->filepath, "index.html");
//     }
    
//     // Check for Range header
//     char *range_header = strstr(req->request_buffer, "Range: bytes=");
//     if (range_header) {
//         req->is_range_request = 1;
//         range_header += 13;  // Skip "Range: bytes="
//         char *range_end = strstr(range_header, "\r\n");
//         if (range_end) {
//             *range_end = '\0';
//             // Will parse actual values after we know file size
//         }
//     }
    
//     // Check for Content-Length (upload)
//     char *content_len = strstr(req->request_buffer, "Content-Length: ");
//     if (content_len) {
//         content_len += 16;
//         req->upload_size = atoll(content_len);
//     }
    
//     return 0;
// }

// int parse_range_header(const char *range_header, off_t *start, off_t *end, off_t file_size) {
//     // Format: "Range: bytes=start-end" or "Range: bytes=start-" or "Range: bytes=-suffix"
//     const char *bytes_pos = strstr(range_header, "bytes=");
//     if (!bytes_pos) {
//         return -1;
//     }
//     bytes_pos += 6;
    
//     if (*bytes_pos == '-') {
//         // Suffix range: -500 means last 500 bytes
//         long suffix = atol(bytes_pos + 1);
//         *start = file_size - suffix;
//         *end = file_size - 1;
//     } else {
//         *start = atoll(bytes_pos);
//         const char *dash = strchr(bytes_pos, '-');
//         if (!dash) {
//             return -1;
//         }
        
//         if (*(dash + 1) == '\0' || *(dash + 1) == '\r') {
//             // Open-ended: 500- means from byte 500 to end
//             *end = file_size - 1;
//         } else {
//             *end = atoll(dash + 1);
//         }
//     }
    
//     // Validate range
//     if (*start < 0 || *end >= file_size || *start > *end) {
//         return -1;
//     }
    
//     return 0;
// }

// // ===== Response Generation =====

// void send_static_response(struct request *req, const char *response) {
//     size_t len = strlen(response);
    
//     struct request *write_req = zh_malloc(sizeof(*write_req) + sizeof(struct iovec));
//     write_req->client_socket = req->client_socket;
//     write_req->iovec_count = 1;
//     write_req->iov[0].iov_base = strdup(response);
//     write_req->iov[0].iov_len = len;
//     write_req->file_fd = -1;
//     write_req->bytes_to_read = 0;
//     write_req->bytes_read = 0;
    
//     add_write_request(write_req);
    
//     // Clean up original request - check all pointers
//     if (req->iov && req->iov[0].iov_base) {
//         free(req->iov[0].iov_base);
//     }
//     if (req->request_buffer) {
//         free(req->request_buffer);
//     }
//     if (req->upload_buffer) {
//         free(req->upload_buffer);
//     }
//     free(req);
// }

// void send_response_headers(struct request *req, int status_code) {
//     char header[2048];
//     const char *status_line;
    
//     switch (status_code) {
//         case 200: status_line = HTTP_200; break;
//         case 206: status_line = HTTP_206; break;
//         case 201: status_line = HTTP_201; break;
//         case 404: status_line = HTTP_404; break;
//         case 416: status_line = HTTP_416; break;
//         default:  status_line = HTTP_500; break;
//     }
    
//     int header_len;
//     if (status_code == 206) {
//         // Partial content response
//         header_len = snprintf(header, sizeof(header),
//             "%s"
//             "Content-Type: %s\r\n"
//             "Content-Length: %ld\r\n"
//             "Content-Range: bytes %ld-%ld/%ld\r\n"
//             "Accept-Ranges: bytes\r\n"
//             "Date: %s\r\n"
//             "%s\r\n",
//             status_line,
//             get_content_type(req->filepath),
//             req->bytes_to_read,
//             req->range_start,
//             req->range_end,
//             req->file_size,
//             get_date_string(),
//             SERVER_STRING);
//     } else if (status_code == 200 && req->file_size > 0) {
//         // Full file response
//         header_len = snprintf(header, sizeof(header),
//             "%s"
//             "Content-Type: %s\r\n"
//             "Content-Length: %ld\r\n"
//             "Accept-Ranges: bytes\r\n"
//             "Date: %s\r\n"
//             "%s\r\n",
//             status_line,
//             get_content_type(req->filepath),
//             req->file_size,
//             get_date_string(),
//             SERVER_STRING);
//     } else if (status_code == 201) {
//         // Upload success
//         header_len = snprintf(header, sizeof(header),
//             "%s"
//             "Content-Length: 0\r\n"
//             "Date: %s\r\n"
//             "%s\r\n",
//             status_line,
//             get_date_string(),
//             SERVER_STRING);
//     } else {
//         // Error response
//         header_len = snprintf(header, sizeof(header),
//             "%s"
//             "Content-Type: text/html\r\n"
//             "Date: %s\r\n"
//             "%s\r\n",
//             status_line,
//             get_date_string(),
//             SERVER_STRING);
//     }
    
//     // Allocate new write request for headers
//     struct request *write_req = zh_malloc(sizeof(*write_req) + sizeof(struct iovec));
//     write_req->client_socket = req->client_socket;
//     write_req->iovec_count = 1;
//     write_req->iov[0].iov_base = strndup(header, header_len);
//     write_req->iov[0].iov_len = header_len;
//     write_req->file_fd = req->file_fd;  // Keep file fd for later reads
    
//     // Copy request info for subsequent file reads
//     memcpy(write_req->filepath, req->filepath, MAX_PATH_LEN);
//     write_req->file_size = req->file_size;
//     write_req->file_offset = req->file_offset;
//     write_req->bytes_to_read = req->bytes_to_read;
//     write_req->bytes_read = 0;
//     write_req->is_upload = req->is_upload;
    
//     add_write_request(write_req);
// }

// // ===== HTTP Handlers =====

// void handle_http_404(struct request *req) {
//     send_static_response(req, ERRORMSG_404);
//     // Don't free here - already freed in send_static_response path
// }

// void handle_range_error(struct request *req) {
//     send_static_response(req, ERRORMSG_416);
// }

// void handle_unimplemented_method(struct request *req) {
//     send_static_response(req, UNIMPLEMENT);
// }

// void handle_get_method(struct request *req) {
//     // Open file directly - we'll get size with fstat after opening
//     add_open_request(req, O_RDONLY, 0);
// }

// void handle_post_method(struct request *req) {
//     // POST data is in the request body after headers
//     // Find the end of headers (blank line)
//     char *body_start = strstr((char *)req->iov[0].iov_base, "\r\n\r\n");
//     if (!body_start) {
//         send_static_response(req, UNIMPLEMENT);
//         return;
//     }
//     body_start += 4; // Skip past "\r\n\r\n"
    
//     // Calculate body size
//     char *buffer_start = (char *)req->iov[0].iov_base;
//     size_t headers_len = body_start - buffer_start;
//     size_t total_read = req->iov[0].iov_len;
    
//     if (total_read <= headers_len) {
//         send_static_response(req, UNIMPLEMENT);
//         return;
//     }
    
//     size_t body_len = total_read - headers_len;
    
//     if (body_len == 0 || body_len > MAX_UPLOAD_SIZE) {
//         send_static_response(req, UNIMPLEMENT);
//         return;
//     }
    
//     // Store upload data
//     req->upload_buffer = malloc(body_len);
//     memcpy(req->upload_buffer, body_start, body_len);
//     req->upload_size = body_len;
//     req->upload_received = body_len;
//     req->is_upload = 1;
    
//     printf("Upload: %zu bytes\n", body_len);
    
//     // Open file for writing
//     add_open_request(req, O_WRONLY | O_CREAT | O_TRUNC, 0644);
// }

// void handle_client_request(struct request *req) {
//     // Parse HTTP request
//     if (parse_http_request(req, req->iov[0].iov_base, req->iov[0].iov_len) < 0) {
//         send_static_response(req, UNIMPLEMENT);
//         return;
//     }
    
//     printf("Request: %s %s\n", req->method, req->filepath);
    
//     if (strcmp(req->method, "get") == 0 || strcmp(req->method, "head") == 0) {
//         handle_get_method(req);
//     } else if (strcmp(req->method, "post") == 0 || strcmp(req->method, "put") == 0) {
//         handle_post_method(req);
//     } else {
//         handle_unimplemented_method(req);
//     }
// }

// // ===== Main Event Loop =====

// void server_loop_uring(int server_socket) {
//     struct io_uring_cqe *cqe;
//     struct sockaddr_in client_addr;
//     socklen_t client_addr_len = sizeof(client_addr);

//     add_accept_request(server_socket, &client_addr, &client_addr_len);

//     while (1) {
//         int ret = io_uring_wait_cqe(&ring, &cqe);
//         if (ret < 0) {
//             fatal_error("io_uring_wait_cqe");
//         }

//         void *user_data = io_uring_cqe_get_data(cqe);
        
//         if (cqe->res < 0 && user_data) {
//             struct request *req = (struct request *)user_data;
//             fprintf(stderr, "Async operation failed: %s (event: %d)\n",
//                     strerror(-cqe->res), req->event_type);
            
//             // Clean up on error
//             if (req->file_fd >= 0) {
//                 close(req->file_fd);
//             }
//             if (req->client_socket >= 0) {
//                 close(req->client_socket);
//             }
//             free(req);
//             io_uring_cqe_seen(&ring, cqe);
//             continue;
//         }

//         // Determine event type and handle
//         struct request *req = (struct request *)user_data;
        
//         switch (req->event_type) {
//             case EVENT_TYPE_ACCEPT: {
//                 int client_fd = cqe->res;
//                 add_accept_request(server_socket, &client_addr, &client_addr_len);
//                 add_read_request(client_fd);
//                 free(req);
//                 break;
//             }
            
//             case EVENT_TYPE_READ: {
//                 if (cqe->res == 0) {
//                     // Connection closed
//                     close(req->client_socket);
//                     free(req->iov[0].iov_base);
//                     free(req);
//                     break;
//                 }
                
//                 handle_client_request(req);
//                 // Don't free req or buffer yet - used in subsequent operations
//                 break;
//             }
            
//             case EVENT_TYPE_OPEN: {
//                 int fd = cqe->res;
//                 if (fd < 0) {
//                     // File not found - send 404
//                     // send_static_response will free everything
//                     send_static_response(req, ERRORMSG_404);
//                     break;
//                 }
                
//                 req->file_fd = fd;
                
//                 if (req->is_upload) {
//                     // Write uploaded data to file
//                     if (req->upload_buffer && req->upload_size > 0) {
//                         ssize_t written = write(req->file_fd, req->upload_buffer, req->upload_size);
//                         if (written < 0) {
//                             close(req->file_fd);
//                             if (req->upload_buffer) free(req->upload_buffer);
//                             send_static_response(req, "HTTP/1.1 500 Internal Server Error\r\n\r\n");
//                             break;
//                         }
//                     }
//                     close(req->file_fd);
                    
//                     // Send success response
//                     struct request *write_req = zh_malloc(sizeof(*write_req) + sizeof(struct iovec));
//                     write_req->client_socket = req->client_socket;
//                     write_req->iovec_count = 1;
//                     write_req->file_fd = -1;
//                     char *response = "HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n";
//                     write_req->iov[0].iov_base = strdup(response);
//                     write_req->iov[0].iov_len = strlen(response);
//                     add_write_request(write_req);
                    
//                     if (req->request_buffer) free(req->request_buffer);
//                     if (req->upload_buffer) free(req->upload_buffer);
//                     if (req->iov[0].iov_base) free(req->iov[0].iov_base);
//                     free(req);
//                 } else {
//                     // Get file size using fstat
//                     struct stat st;
//                     if (fstat(req->file_fd, &st) < 0) {
//                         close(req->file_fd);
//                         send_static_response(req, ERRORMSG_404);
//                         break;
//                     }
                    
//                     req->file_size = st.st_size;
                    
//                     // Parse range if present
//                     if (req->is_range_request) {
//                         char *range_header = strstr(req->request_buffer, "Range: ");
//                         if (range_header && parse_range_header(range_header, &req->range_start, 
//                                                                &req->range_end, req->file_size) == 0) {
//                             req->file_offset = req->range_start;
//                             req->bytes_to_read = req->range_end - req->range_start + 1;
//                         } else {
//                             close(req->file_fd);
//                             send_static_response(req, ERRORMSG_416);
//                             break;
//                         }
//                     } else {
//                         req->file_offset = 0;
//                         req->bytes_to_read = req->file_size;
//                         req->range_start = 0;
//                         req->range_end = req->file_size - 1;
//                     }
                    
//                     // Send headers and prepare for file reading
//                     send_response_headers(req, req->is_range_request ? 206 : 200);
//                     if (req->request_buffer) free(req->request_buffer);
//                     if (req->iov[0].iov_base) free(req->iov[0].iov_base);
//                     free(req);
//                 }
//                 break;
//             }
            
//             case EVENT_TYPE_WRITE: {
//                 // After headers are written, start reading file if needed
//                 if (req->file_fd >= 0 && req->bytes_read < req->bytes_to_read) {
//                     add_file_read_request(req);
//                 } else {
//                     // All done - close connection
//                     for (int i = 0; i < req->iovec_count; i++) {
//                         free(req->iov[i].iov_base);
//                     }
//                     if (req->file_fd >= 0) {
//                         close(req->file_fd);
//                     }
//                     if (req->client_socket >= 0) {
//                         close(req->client_socket);
//                     }
//                     free(req);
//                 }
//                 break;
//             }
            
//             case EVENT_TYPE_FILE_READ: {
//                 size_t bytes_read = cqe->res;
                
//                 if (bytes_read <= 0) {
//                     // Error or EOF
//                     free(req->iov[0].iov_base);
//                     if (req->file_fd >= 0) close(req->file_fd);
//                     close(req->client_socket);
//                     free(req);
//                     break;
//                 }
                
//                 // Create write request with the data we just read
//                 struct request *write_req = zh_malloc(sizeof(*write_req) + sizeof(struct iovec));
//                 write_req->event_type = EVENT_TYPE_WRITE;
//                 write_req->client_socket = req->client_socket;
//                 write_req->file_fd = req->file_fd;
//                 write_req->iovec_count = 1;
                
//                 // Transfer buffer ownership to write request
//                 write_req->iov[0].iov_base = req->iov[0].iov_base;
//                 write_req->iov[0].iov_len = bytes_read;
                
//                 // Update progress tracking
//                 write_req->bytes_read = req->bytes_read + bytes_read;
//                 write_req->bytes_to_read = req->bytes_to_read;
//                 write_req->file_offset = req->file_offset + bytes_read;
                
//                 add_write_request(write_req);
                
//                 // Free the read request (buffer ownership transferred)
//                 free(req);
//                 break;
//             }
            
//             case EVENT_TYPE_CLOSE: {
//                 free(req);
//                 break;
//             }
            
//             default:
//                 fprintf(stderr, "Unknown event type: %d\n", req->event_type);
//                 free(req);
//                 break;
//         }

//         io_uring_cqe_seen(&ring, cqe);
//     }
// }

// void sigint_handler(int signo) {
//     printf("\n^C pressed. Shutting down.\n");
//     io_uring_queue_exit(&ring);
//     exit(0);
// }

// int main(int argc, char *argv[]) {
//     int port = DEFAULT_SERVER_PORT;
    
//     if (argc > 1) {
//         port = atoi(argv[1]);
//     }
    
//     if (check_kernel_version()) {
//         return EXIT_FAILURE;
//     }

//     int server_socket = setup_listening_socket(port);
//     printf("Static File Server listening on port %d\n", port);
//     printf("Document root: current directory\n");
//     printf("Supported: GET (with Range), POST/PUT (upload)\n\n");

//     signal(SIGINT, sigint_handler);
    
//     if (io_uring_queue_init(QUEUE_DEPTH, &ring, 0) < 0) {
//         fatal_error("io_uring_queue_init");
//     }
    
//     server_loop_uring(server_socket);

//     return 0;
// }