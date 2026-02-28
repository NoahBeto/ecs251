#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define READ_SZ 8192
#define MAX_EVENTS 100
#define MAX_PATH_LEN 512
#define MAX_UPLOAD_SIZE (100 * 1024 * 1024)

struct request {
    int client_socket;
    int file_fd;

    // File info
    char filepath[MAX_PATH_LEN];
    off_t file_size;
    off_t file_offset;
    off_t bytes_to_read;

    // Range request
    int is_range_request;
    off_t range_start;
    off_t range_end;

    // Upload support
    int is_upload;
    int upload_fd;
    off_t upload_size;
    off_t upload_received;

    char method[16];
};

void fatal_error(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

char *get_date_string(void) {
    static char buf[128];
    time_t now = time(NULL);
    struct tm *tm = gmtime(&now);
    strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S GMT", tm);
    return buf;
}

const char *get_content_type(const char *path) {
    const char *dot = strrchr(path, '.');
    if (!dot) return "application/octet-stream";
    if (strcasecmp(dot, ".html") == 0 || strcasecmp(dot, ".htm") == 0) return "text/html";
    if (strcasecmp(dot, ".txt") == 0) return "text/plain";
    if (strcasecmp(dot, ".jpg") == 0 || strcasecmp(dot, ".jpeg") == 0) return "image/jpeg";
    if (strcasecmp(dot, ".png") == 0) return "image/png";
    if (strcasecmp(dot, ".pdf") == 0) return "application/pdf";
    return "application/octet-stream";
}

int parse_range_header(const char *buffer, off_t *start, off_t *end, off_t file_size) {
    const char *range_ptr = strstr(buffer, "Range: bytes=");
    if (!range_ptr) return -1;
    range_ptr += 13;
    if (*range_ptr == '-') {
        long suffix = atol(range_ptr + 1);
        *start = (file_size > suffix) ? (file_size - suffix) : 0;
        *end = file_size - 1;
    } else {
        *start = atoll(range_ptr);
        const char *dash = strchr(range_ptr, '-');
        if (dash && *(dash + 1) != '\0' && isdigit(*(dash + 1))) {
            *end = atoll(dash + 1);
        } else {
            *end = file_size - 1;
        }
    }
    if (*start < 0 || *start >= file_size || *start > *end) return -2;
    if (*end >= file_size) *end = file_size - 1;
    return 0;
}

void send_response_headers(struct request *req, int status_code) {
    char header[2048];
    const char *status_line;
    switch (status_code) {
        case 200: status_line = "HTTP/1.1 200 OK\r\n"; break;
        case 206: status_line = "HTTP/1.1 206 Partial Content\r\n"; break;
        case 201: status_line = "HTTP/1.1 201 Created\r\n"; break;
        case 416: status_line = "HTTP/1.1 416 Range Not Satisfiable\r\n"; break;
        default: status_line = "HTTP/1.1 404 Not Found\r\n"; break;
    }
    int len;
    if (status_code == 206) {
        len = snprintf(header, sizeof(header),
                       "%sContent-Type: %s\r\nContent-Length: %ld\r\n"
                       "Content-Range: bytes %ld-%ld/%ld\r\nAccept-Ranges: bytes\r\n"
                       "Date: %s\r\nServer: EpollServer\r\nConnection: close\r\n\r\n",
                       status_line, get_content_type(req->filepath), req->bytes_to_read,
                       req->range_start, req->range_end, req->file_size, get_date_string());
    } else {
        len = snprintf(header, sizeof(header),
                       "%sContent-Type: %s\r\nContent-Length: %ld\r\nAccept-Ranges: bytes\r\n"
                       "Date: %s\r\nServer: EpollServer\r\nConnection: close\r\n\r\n",
                       status_line, get_content_type(req->filepath), req->bytes_to_read, get_date_string());
    }
    send(req->client_socket, header, len, 0);
}

int setup_listening_socket(int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) fatal_error("socket");
    int enable = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) fatal_error("bind");
    if (listen(sock, 128) < 0) fatal_error("listen");
    return sock;
}

void server_loop_epoll(int server_socket) {
    int epoll_fd = epoll_create1(0);
    struct epoll_event ev, events[MAX_EVENTS];
    ev.events = EPOLLIN;
    ev.data.fd = server_socket;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_socket, &ev);

    while (1) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == server_socket) {
                int client_fd = accept(server_socket, NULL, NULL);
                if (client_fd < 0) continue;
                fcntl(client_fd, F_SETFL, fcntl(client_fd, F_GETFL) | O_NONBLOCK);
                struct request *req = calloc(1, sizeof(struct request));
                req->client_socket = client_fd;
                req->file_fd = -1;
                req->upload_fd = -1;
                struct epoll_event c_ev = {.events = EPOLLIN | EPOLLET, .data.ptr = req};
                epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &c_ev);
                continue;
            }

            struct request *req = (struct request *)events[i].data.ptr;

            if (events[i].events & EPOLLIN) {
                char buf[READ_SZ] = {0};
                ssize_t n = recv(req->client_socket, buf, sizeof(buf), 0);
                if (n <= 0) goto close_conn;

                // 解析方法和路径
                if (sscanf(buf, "%s /%s", req->method, req->filepath) < 2) strcpy(req->filepath, "index.html");
                char *space = strchr(req->filepath, ' '); if (space) *space = '\0';

                // POST/PUT 上传
                if (strcasecmp(req->method, "POST") == 0 || strcasecmp(req->method, "PUT") == 0) {
                    req->is_upload = 1;
                    req->upload_fd = open(req->filepath, O_CREAT | O_WRONLY | O_TRUNC | O_NONBLOCK, 0644);
                    if (req->upload_fd < 0) goto close_conn;

                    char *body = strstr(buf, "\r\n\r\n");
                    if (body) {
                        body += 4;
                        ssize_t written = write(req->upload_fd, body, n - (body - buf));
                        req->upload_received += written;
                    }

                    // 解析 Content-Length
                    char *cl = strcasestr(buf, "Content-Length:");
                    if (cl) req->upload_size = atol(cl + 15);

                    continue;
                }

                // GET/Range
                int ffd = open(req->filepath, O_RDONLY);
                if (ffd != -1) {
                    struct stat st; fstat(ffd, &st);
                    req->file_size = st.st_size;
                    int res = parse_range_header(buf, &req->range_start, &req->range_end, st.st_size);
                    if (res == -2) {
                        req->bytes_to_read = 0;
                        send_response_headers(req, 416);
                        close(ffd);
                        goto close_conn;
                    } else if (res == 0) {
                        req->file_offset = req->range_start;
                        req->bytes_to_read = req->range_end - req->range_start + 1;
                        send_response_headers(req, 206);
                    } else {
                        req->file_offset = 0;
                        req->bytes_to_read = st.st_size;
                        send_response_headers(req, 200);
                    }
                    req->file_fd = ffd;
                    struct epoll_event o_ev = {.events = EPOLLOUT | EPOLLET, .data.ptr = req};
                    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, req->client_socket, &o_ev);
                } else {
                    req->bytes_to_read = 0;
                    send_response_headers(req, 404);
                    goto close_conn;
                }
            }
            else if (events[i].events & EPOLLOUT) {
                if (req->is_upload) {
                    char buf[READ_SZ];
                    ssize_t n = recv(req->client_socket, buf, sizeof(buf), 0);
                    if (n > 0) {
                        ssize_t w = write(req->upload_fd, buf, n);
                        req->upload_received += w;
                    }
                    if (req->upload_received >= req->upload_size) {
                        send_response_headers(req, 201);
                        close(req->upload_fd);
                        req->upload_fd = -1;
                        req->is_upload = 0;
                        goto close_conn;
                    }
                    continue;
                }

                char chunk[8192];
                while (req->bytes_to_read > 0) {
                    size_t to_read = req->bytes_to_read > sizeof(chunk) ? sizeof(chunk) : req->bytes_to_read;
                    ssize_t r = pread(req->file_fd, chunk, to_read, req->file_offset);
                    if (r <= 0) break;
                    ssize_t total_sent = 0;
                    while (total_sent < r) {
                        ssize_t s = send(req->client_socket, chunk + total_sent, r - total_sent, 0);
                        if (s < 0) {
                            if (errno == EAGAIN || errno == EWOULDBLOCK) goto out_loop;
                            goto close_conn;
                        }
                        total_sent += s;
                    }
                    req->file_offset += r;
                    req->bytes_to_read -= r;
                }
            out_loop:
                if (req->bytes_to_read <= 0) goto close_conn;
            }

            continue;

        close_conn:
            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, req->client_socket, NULL);
            if (req->file_fd >= 0) close(req->file_fd);
            if (req->upload_fd >= 0) close(req->upload_fd);
            close(req->client_socket);
            free(req);
        }
    }
}

int main(int argc, char *argv[]) {
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, exit);

    int port = (argc > 1) ? atoi(argv[1]) : 8000;
    int server_sock = setup_listening_socket(port);
    printf("Epoll Server listening on %d\n", port);

    server_loop_epoll(server_sock);
    return 0;
}