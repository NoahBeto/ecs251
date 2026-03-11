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

#define MAX_EVENTS 1024
#define BUFFER_SIZE 8192

// Simple structure to hold client connection info
typedef struct {
    int fd;
    off_t file_offset;
    off_t file_size;
    int file_fd;
} client_t;

char *get_file_path(char *request) {
    // Very basic HTTP GET parser
    if (strncmp(request, "GET ", 4) != 0) return NULL;
    char *path = request + 4;
    char *space = strchr(path, ' ');
    if (!space) return NULL;
    *space = 0;
    return path + 1; // skip leading '/'
}

// Send file data with optional range support
int send_file_range(client_t *client, off_t start, off_t end) {
    char header[512];
    off_t len = end - start + 1;
    int n;

    if (start > 0) {
        n = snprintf(header, sizeof(header),
                     "HTTP/1.1 206 Partial Content\r\n"
                     "Content-Length: %ld\r\n"
                     "Content-Range: bytes %ld-%ld/%ld\r\n"
                     "Connection: close\r\n\r\n",
                     len, start, end, client->file_size);
    } else {
        n = snprintf(header, sizeof(header),
                     "HTTP/1.1 200 OK\r\n"
                     "Content-Length: %ld\r\n"
                     "Connection: close\r\n\r\n",
                     len);
    }

    if (write(client->fd, header, n) < 0) return -1;

    off_t offset = start;
    while (offset <= end) {
        ssize_t sent = sendfile(client->fd, client->file_fd, &offset, end - offset + 1);
        if (sent <= 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            return -1;
        }
    }
    return 0;
}

// Parse optional Range header: "Range: bytes=start-end"
int parse_range(const char *request, off_t *start, off_t *end, off_t file_size) {
    const char *range_prefix = "Range: bytes=";
    char *range = strstr(request, range_prefix);
    if (!range) return 0; // no range

    range += strlen(range_prefix);
    if (sscanf(range, "%ld-%ld", start, end) < 1) return -1;

    if (*end == 0 || *end >= file_size) *end = file_size - 1;
    if (*start > *end) return -1;
    return 1;
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
    listen(s, 128);
    return s;
}

int main(int argc, char *argv[]) {
    int port = 8000;
    if (argc > 1) port = atoi(argv[1]);

    int listen_fd = make_socket(port);
    int epoll_fd = epoll_create1(0);
    struct epoll_event ev, events[MAX_EVENTS];

    ev.events = EPOLLIN;
    ev.data.fd = listen_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &ev);

    while (1) {
        int n = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        for (int i = 0; i < n; i++) {
            if (events[i].data.fd == listen_fd) {
                int client_fd = accept(listen_fd, NULL, NULL);
                fcntl(client_fd, F_SETFL, O_NONBLOCK);
                client_t *client = calloc(1, sizeof(client_t));
                client->fd = client_fd;
                ev.events = EPOLLIN | EPOLLET;
                ev.data.ptr = client;
                epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev);
            } else {
                client_t *client = events[i].data.ptr;
                char buf[BUFFER_SIZE];
                int len = read(client->fd, buf, sizeof(buf) - 1);
                if (len <= 0) {
                    close(client->fd);
                    if (client->file_fd > 0) close(client->file_fd);
                    free(client);
                    continue;
                }
                buf[len] = 0;

                char *path = get_file_path(buf);
                if (!path) { close(client->fd); free(client); continue; }

                client->file_fd = open(path, O_RDONLY);
                if (client->file_fd < 0) {
                    const char *resp = "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n";
                    write(client->fd, resp, strlen(resp));
                    close(client->fd);
                    free(client);
                    continue;
                }

                struct stat st;
                fstat(client->file_fd, &st);
                client->file_size = st.st_size;

                off_t start = 0, end = client->file_size - 1;
                parse_range(buf, &start, &end, client->file_size);

                send_file_range(client, start, end);

                close(client->file_fd);
                close(client->fd);
                free(client);
            }
        }
    }
}