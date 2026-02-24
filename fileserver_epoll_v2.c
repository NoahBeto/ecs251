#include "fileserver.h"
#include <ctype.h>
#include <signal.h>
#include <sys/epoll.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>



void fatal_error(const char *syscall) {
    perror(syscall);
    exit(EXIT_FAILURE);
}

void *zh_malloc(size_t size) {
    void *ptr = calloc(1, size);
    if (!ptr) fatal_error("malloc");
    return ptr;
}

int setup_listening_socket(int port) {
    int sock;
    struct sockaddr_in srv_addr;
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) fatal_error("socket");

    int enable = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));

    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(port);
    srv_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (const struct sockaddr *)&srv_addr, sizeof(srv_addr)) < 0)
        fatal_error("bind");

    if (listen(sock, 128) < 0) fatal_error("listen");
    return sock;
}

const char *get_content_type(const char *path) {
    if (strstr(path, ".html")) return "text/html";
    if (strstr(path, ".txt")) return "text/plain";
    return "application/octet-stream";
}


int parse_range_header(const char *range_header, off_t *start, off_t *end, off_t file_size) {
    char *range_ptr = strstr(range_header, "Range: bytes=");
    if (!range_ptr) {
        *start = 0; *end = file_size - 1;
        return -1;
    }

    range_ptr += 13; 
    if (*range_ptr == '-') {

        long suffix = atol(range_ptr + 1);
        *start = (file_size > suffix) ? (file_size - suffix) : 0;
        *end = file_size - 1;
    } else {

        *start = atol(range_ptr);
        char *dash = strchr(range_ptr, '-');
        if (dash && *(dash + 1) != '\0' && isdigit(*(dash + 1))) {
            *end = atol(dash + 1);
        } else {
            *end = file_size - 1;
        }
    }

    if (*start < 0) *start = 0;
    if (*end >= file_size) *end = file_size - 1;
    if (*start > *end) *start = *end; 
    return 0;
}


void send_response(struct request *req, int status_code, off_t start, off_t end) {
    char header[1024];
    const char *status_line;
    if (status_code == 200) status_line = "HTTP/1.1 200 OK";
    else if (status_code == 206) status_line = "HTTP/1.1 206 Partial Content";
    else if (status_code == 201) status_line = "HTTP/1.1 201 Created";
    else status_line = "HTTP/1.1 404 Not Found";

    off_t content_length = (status_code == 404 || status_code == 201) ? 0 : (end - start + 1);

    int len = snprintf(header, sizeof(header),
             "%s\r\n"
             "Content-Type: %s\r\n"
             "Content-Length: %ld\r\n"
             "Accept-Ranges: bytes\r\n"
             "Server: Gemini-Epoll-Server\r\n"
             "Connection: close\r\n"
             "\r\n", 
             status_line, get_content_type(req->filepath), content_length);
    
    send(req->client_socket, header, len, 0);
    req->file_offset = start;
    req->file_size = end + 1; 
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
                
                int flags = fcntl(client_fd, F_GETFL, 0);
                fcntl(client_fd, F_SETFL, flags | O_NONBLOCK);

                struct request *req = zh_malloc(sizeof(struct request));
                req->client_socket = client_fd;
                req->file_fd = -1;
                struct epoll_event c_ev = {.events = EPOLLIN | EPOLLET, .data.ptr = req};
                epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &c_ev);
                continue;
            }

            struct request *req = (struct request *)events[i].data.ptr;
            
            if (events[i].events & EPOLLIN) {
                char buf[8192] = {0};
                ssize_t n = recv(req->client_socket, buf, sizeof(buf)-1, 0);
                if (n <= 0) goto close_conn;

                char method[16], path[256];
                if (sscanf(buf, "%s /%s", method, path) < 2) strcpy(path, "index.html");
                char *space = strchr(path, ' '); if (space) *space = '\0';
                strcpy(req->filepath, path);

                if (strncasecmp(method, "POST", 4) == 0) {
                    char *body = strstr(buf, "\r\n\r\n");
                    if (body) {
                        body += 4;
                        size_t body_len = n - (body - buf);
                        int wfd = open(req->filepath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
                        if (wfd != -1) {
                            write(wfd, body, body_len);
                            close(wfd);
                        }
                    }
                    send_response(req, 201, 0, 0);
                    goto close_conn;
                }

                int ffd = open(req->filepath, O_RDONLY);
                if (ffd != -1) {
                    struct stat st; fstat(ffd, &st);
                    off_t start, end;
                    int is_range = parse_range_header(buf, &start, &end, st.st_size);
                    
                    if (strncasecmp(method, "HEAD", 4) == 0) {
                        req->file_size = st.st_size;
                        send_response(req, 200, 0, st.st_size - 1);
                        close(ffd);
                        goto close_conn;
                    }

                    req->file_fd = ffd;
                    send_response(req, (is_range == 0) ? 206 : 200, start, end);
                    struct epoll_event o_ev = {.events = EPOLLOUT | EPOLLET, .data.ptr = req};
                    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, req->client_socket, &o_ev);
                } else {
                    send_response(req, 404, 0, 0);
                    goto close_conn;
                }
            } 
            else if (events[i].events & EPOLLOUT) {
                char chunk[8192];
                while (req->file_offset < req->file_size) {
                    off_t to_read = (req->file_size - req->file_offset > 8192) ? 8192 : (req->file_size - req->file_offset);
                    ssize_t r = pread(req->file_fd, chunk, to_read, req->file_offset);
                    if (r <= 0) goto close_conn; 

                    ssize_t s = send(req->client_socket, chunk, r, 0);
                    if (s <= 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        goto close_conn;
                    }
                    req->file_offset += s;
                }
                if (req->file_offset >= req->file_size) goto close_conn;
            }
            continue;

        close_conn:
            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, req->client_socket, NULL);
            if (req->file_fd > 0) close(req->file_fd);
            close(req->client_socket);
            free(req);
        }
    }
}

int main(int argc, char *argv[]) {
    signal(SIGPIPE, SIG_IGN);
    int port = (argc > 1) ? atoi(argv[1]) : 8000;
    int server_sock = setup_listening_socket(port);
    printf("Epoll Server listening on %d\n", port);
    server_loop_epoll(server_sock);
    return 0;
}