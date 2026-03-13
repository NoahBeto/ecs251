#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/epoll.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>

#define MAX_EVENTS 10240
#define BUFFER_SIZE 8192

typedef enum { STATE_READING, STATE_WRITING, STATE_DONE } client_state_t;

typedef struct {
    int fd;
    int file_fd;
    off_t file_offset;
    off_t file_size;
    off_t range_start;
    off_t range_end;
    char buf[BUFFER_SIZE];
    int buf_len;
    int buf_sent;
    client_state_t state;
} client_t;

// Simple HTTP GET parser
char *get_file_path(char *request) {
    if (strncmp(request, "GET ", 4) != 0) return NULL;
    char *path = request + 4;
    char *space = strchr(path, ' ');
    if (!space) return NULL;
    *space = 0;
    return path + 1;
}

// Parse optional Range header: "Range: bytes=start-end"
int parse_range(const char *request, off_t *start, off_t *end, off_t file_size) {
    const char *range_prefix = "Range: bytes=";
    char *range = strstr(request, range_prefix);
    if (!range) return 0; // no range

    range += strlen(range_prefix);
    if (sscanf(range, "%ld-%ld", start, end) < 1) return -1;

    if (*end <= 0 || *end >= file_size) *end = file_size - 1;
    if (*start > *end) return -1;
    return 1;
}

// Set non-blocking
void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

// Add client to epoll
void add_client(int epoll_fd, int client_fd) {
    set_nonblocking(client_fd);
    client_t *client = calloc(1, sizeof(client_t));
    client->fd = client_fd;
    client->state = STATE_READING;

    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET;
    ev.data.ptr = client;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev);
}

// Build HTTP response headers
int build_headers(client_t *client, int partial) {
    char header[512];
    off_t len = client->range_end - client->range_start + 1;
    int n;

    if (partial) {
        n = snprintf(header, sizeof(header),
                     "HTTP/1.1 206 Partial Content\r\n"
                     "Content-Length: %ld\r\n"
                     "Content-Range: bytes %ld-%ld/%ld\r\n"
                     "Connection: close\r\n\r\n",
                     len, client->range_start, client->range_end, client->file_size);
    } else {
        n = snprintf(header, sizeof(header),
                     "HTTP/1.1 200 OK\r\n"
                     "Content-Length: %ld\r\n"
                     "Connection: close\r\n\r\n",
                     len);
    }

    memcpy(client->buf, header, n);
    client->buf_len = n;
    client->buf_sent = 0;
    client->file_offset = client->range_start;
    client->state = STATE_WRITING;
    return 0;
}

// Close client and free
void close_client(client_t *client, int epoll_fd) {
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client->fd, NULL);
    close(client->fd);
    if (client->file_fd > 0) close(client->file_fd);
    free(client);
}

// Handle readable client
void handle_read(client_t *client, int epoll_fd) {
    while (1) {
        ssize_t n = read(client->fd, client->buf, sizeof(client->buf) - 1);
        if (n == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            close_client(client, epoll_fd);
            return;
        } else if (n == 0) {
            close_client(client, epoll_fd);
            return;
        } else {
            client->buf[n] = 0;
            char *path = get_file_path(client->buf);
            if (!path) { close_client(client, epoll_fd); return; }

            client->file_fd = open(path, O_RDONLY);
            if (client->file_fd < 0) {
                const char *resp = "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n";
                write(client->fd, resp, strlen(resp));
                close_client(client, epoll_fd);
                return;
            }

            struct stat st;
            fstat(client->file_fd, &st);
            client->file_size = st.st_size;
            client->range_start = 0;
            client->range_end = client->file_size - 1;

            parse_range(client->buf, &client->range_start, &client->range_end, client->file_size);
            build_headers(client, client->range_start > 0);
            
            // Switch to EPOLLOUT
            struct epoll_event ev;
            ev.events = EPOLLOUT | EPOLLET;
            ev.data.ptr = client;
            epoll_ctl(epoll_fd, EPOLL_CTL_MOD, client->fd, &ev);
            return;
        }
    }
}

// Handle writable client
void handle_write(client_t *client, int epoll_fd) {
    while (1) {
        // Send remaining headers first
        while (client->buf_sent < client->buf_len) {
            ssize_t n = write(client->fd, client->buf + client->buf_sent, client->buf_len - client->buf_sent);
            if (n == -1) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) return;
                close_client(client, epoll_fd);
                return;
            }
            client->buf_sent += n;
        }

        // Send file data using non-blocking sendfile
        while (client->file_offset <= client->range_end) {
            off_t offset = client->file_offset;
            ssize_t n = sendfile(client->fd, client->file_fd, &offset, client->range_end - client->file_offset + 1);
            if (n == -1) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) return;
                close_client(client, epoll_fd);
                return;
            }
            client->file_offset += n;
        }

        close_client(client, epoll_fd);
        return;
    }
}

int make_socket(int port) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    bind(s, (struct sockaddr*)&addr, sizeof(addr));
    listen(s, 65535);
    set_nonblocking(s);
    return s;
}

int main(int argc, char *argv[]) {
    int port = 8000;
    if (argc > 1) port = atoi(argv[1]);

    int listen_fd = make_socket(port);
    int epoll_fd = epoll_create1(0);
    struct epoll_event ev, events[MAX_EVENTS];

    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = listen_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &ev);

    while (1) {
        int n = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        for (int i = 0; i < n; i++) {
            if (events[i].data.fd == listen_fd) {
                while (1) {
                    int client_fd = accept(listen_fd, NULL, NULL);
                    if (client_fd == -1) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        perror("accept");
                        break;
                    }
                    add_client(epoll_fd, client_fd);
                }
            } else {
                client_t *client = events[i].data.ptr;
                if (events[i].events & EPOLLIN) handle_read(client, epoll_fd);
                if (events[i].events & EPOLLOUT) handle_write(client, epoll_fd);
            }
        }
    }
}