// #define _GNU_SOURCE
// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include <unistd.h>
// #include <fcntl.h>
// #include <signal.h>
// #include <ctype.h>
// #include <errno.h>
// #include <time.h>
// #include <limits.h>
// #include <sys/stat.h>
// #include <sys/epoll.h>
// #include <arpa/inet.h>
// #include <netinet/in.h>

// /* ── tunables ─────────────────────────────────────────────────── */
// #define READ_SZ           65536
// #define MAX_EVENTS        1024
// #define MAX_PATH_LEN      512
// #define MAX_UPLOAD_SIZE   (100 * 1024 * 1024)
// #define HEADER_BUF_SZ     8192
// #define PUBLIC_ROOT       "." // "../public"
// #define UPLOAD_DIR        "../uploads"

// /* ── connection state ─────────────────────────────────────────── */
// typedef enum {
//     STATE_READING_HEADERS,
//     STATE_SENDING_FILE,
//     STATE_RECEIVING_UPLOAD,
// } conn_state_t;

// struct conn {
//     int            fd;
//     conn_state_t   state;

//     /* Header accumulation (only used during STATE_READING_HEADERS) */
//     char           hdr_buf[HEADER_BUF_SZ];
//     int            hdr_len;

//     /* Parsed fields */
//     char           method[16];
//     char           filepath[MAX_PATH_LEN];

//     /* File serving */
//     int            file_fd;
//     off_t          file_size;
//     off_t          file_offset;
//     off_t          bytes_to_send;
//     int            is_range;
//     off_t          range_start;
//     off_t          range_end;

//     /* Upload */
//     int            upload_fd;
//     off_t          upload_expected;
//     off_t          upload_received;
// };

// /* ── forward declarations ─────────────────────────────────────── */
// static int  setup_listening_socket(int port);
// static void handle_read (int epfd, struct conn *c);
// static void handle_write(int epfd, struct conn *c);
// static void close_conn  (int epfd, struct conn *c);
// static void process_headers(int epfd, struct conn *c);

// /* ── tiny helpers ─────────────────────────────────────────────── */

// static void fatal(const char *msg) { perror(msg); exit(EXIT_FAILURE); }

// static void set_nonblocking(int fd)
// {
//     int f = fcntl(fd, F_GETFL, 0);
//     if (f < 0 || fcntl(fd, F_SETFL, f | O_NONBLOCK) < 0) fatal("fcntl");
// }

// static const char *date_str(void)
// {
//     static char buf[64];
//     time_t now = time(NULL);
//     strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S GMT", gmtime(&now));
//     return buf;
// }

// static const char *content_type(const char *path)
// {
//     const char *d = strrchr(path, '.');
//     if (!d) return "application/octet-stream";
//     if (!strcasecmp(d,".html")||!strcasecmp(d,".htm")) return "text/html";
//     if (!strcasecmp(d,".txt"))  return "text/plain";
//     if (!strcasecmp(d,".css"))  return "text/css";
//     if (!strcasecmp(d,".js"))   return "application/javascript";
//     if (!strcasecmp(d,".json")) return "application/json";
//     if (!strcasecmp(d,".jpg")||!strcasecmp(d,".jpeg")) return "image/jpeg";
//     if (!strcasecmp(d,".png"))  return "image/png";
//     if (!strcasecmp(d,".gif"))  return "image/gif";
//     if (!strcasecmp(d,".svg"))  return "image/svg+xml";
//     if (!strcasecmp(d,".pdf"))  return "application/pdf";
//     return "application/octet-stream";
// }

// /* Resolve url_path safely under root_dir. Returns 0 or -1. */
// static int resolve_path(const char *root_dir, const char *url_path,
//                         char *out, size_t outsz)
// {
//     char candidate[PATH_MAX];
//     if (strcmp(url_path, "/") == 0)
//         snprintf(candidate, sizeof(candidate), "%s/index.html", root_dir);
//     else
//         snprintf(candidate, sizeof(candidate), "%s%s", root_dir, url_path);

//     char resolved_root[PATH_MAX];
//     if (!realpath(root_dir, resolved_root)) return -1;

//     char resolved_file[PATH_MAX];
//     if (!realpath(candidate, resolved_file)) {
//         /* File may not exist yet (upload target) – reject ".." */
//         if (strstr(candidate, "..")) return -1;
//         snprintf(out, outsz, "%s", candidate);
//         return 0;
//     }

//     size_t rlen = strlen(resolved_root);
//     if (strncmp(resolved_file, resolved_root, rlen) != 0 ||
//         (resolved_file[rlen] != '/' && resolved_file[rlen] != '\0'))
//         return -1;

//     snprintf(out, outsz, "%s", resolved_file);
//     return 0;
// }

// /* ── response helpers ─────────────────────────────────────────── */

// static void send_error(int fd, int code, const char *msg)
// {
//     char body[256], hdr[512];
//     int blen = snprintf(body, sizeof(body),
//         "<html><body><h1>%d %s</h1></body></html>\r\n", code, msg);
//     int hlen = snprintf(hdr, sizeof(hdr),
//         "HTTP/1.1 %d %s\r\n"
//         "Content-Type: text/html\r\nContent-Length: %d\r\n"
//         "Connection: close\r\nDate: %s\r\n\r\n",
//         code, msg, blen, date_str());
//     send(fd, hdr,  hlen, MSG_NOSIGNAL);
//     send(fd, body, blen, MSG_NOSIGNAL);
// }

// static void send_file_headers(struct conn *c, int code)
// {
//     char hdr[1024];
//     const char *status =
//         code == 206 ? "206 Partial Content" :
//         code == 201 ? "201 Created"         : "200 OK";
//     int n;
//     if (code == 206) {
//         n = snprintf(hdr, sizeof(hdr),
//             "HTTP/1.1 %s\r\nContent-Type: %s\r\nContent-Length: %lld\r\n"
//             "Content-Range: bytes %lld-%lld/%lld\r\nAccept-Ranges: bytes\r\n"
//             "Date: %s\r\nServer: EpollServer\r\nConnection: keep-alive\r\n\r\n",
//             status, content_type(c->filepath), (long long)c->bytes_to_send,
//             (long long)c->range_start, (long long)c->range_end,
//             (long long)c->file_size, date_str());
//     } else {
//         n = snprintf(hdr, sizeof(hdr),
//             "HTTP/1.1 %s\r\nContent-Type: %s\r\nContent-Length: %lld\r\n"
//             "Accept-Ranges: bytes\r\nDate: %s\r\nServer: EpollServer\r\n"
//             "Connection: keep-alive\r\n\r\n",
//             status, content_type(c->filepath),
//             (long long)c->bytes_to_send, date_str());
//     }
//     send(c->fd, hdr, n, MSG_NOSIGNAL);
// }

// /* ── Range parser ─────────────────────────────────────────────── */

// static int parse_range(const char *hdrs, off_t fsz, off_t *s, off_t *e)
// {
//     const char *p = strcasestr(hdrs, "Range: bytes=");
//     if (!p) return -1;
//     p += 13;
//     if (*p == '-') {
//         long long suf = atoll(p + 1);
//         if (suf <= 0) return -2;
//         *s = fsz > suf ? fsz - suf : 0;
//         *e = fsz - 1;
//     } else {
//         *s = atoll(p);
//         const char *dash = strchr(p, '-');
//         *e = (dash && isdigit((unsigned char)dash[1])) ? atoll(dash+1) : fsz-1;
//     }
//     if (*s < 0 || *s >= fsz || *s > *e) return -2;
//     if (*e >= fsz) *e = fsz - 1;
//     return 0;
// }

// /* ── Connection teardown ──────────────────────────────────────── */

// static void close_conn(int epfd, struct conn *c)
// {
//     epoll_ctl(epfd, EPOLL_CTL_DEL, c->fd, NULL);
//     close(c->fd);
//     if (c->file_fd   >= 0) close(c->file_fd);
//     if (c->upload_fd >= 0) close(c->upload_fd);
//     free(c);
// }

// /* ── Switch a connection to EPOLLOUT ──────────────────────────── */

// static void watch_write(int epfd, struct conn *c)
// {
//     struct epoll_event ev = { .events = EPOLLOUT | EPOLLET, .data.ptr = c };
//     epoll_ctl(epfd, EPOLL_CTL_MOD, c->fd, &ev);
// }

// /* ── Parse completed headers and start serving ────────────────── */

// static void process_headers(int epfd, struct conn *c)
// {
//     const char *hdrs = c->hdr_buf;
//     char *eoh = strstr(c->hdr_buf, "\r\n\r\n"); /* caller verified non-NULL */

//     char raw_url[MAX_PATH_LEN] = "/";
//     if (sscanf(hdrs, "%15s %511s", c->method, raw_url) < 2) {
//         send_error(c->fd, 400, "Bad Request");
//         close_conn(epfd, c); return;
//     }
//     char *qs = strchr(raw_url, '?');
//     if (qs) *qs = '\0';

//     int is_upload = (strcasecmp(c->method,"POST")==0 ||
//                      strcasecmp(c->method,"PUT") ==0);

//     const char *root = is_upload ? UPLOAD_DIR : PUBLIC_ROOT;
//     if (resolve_path(root, raw_url, c->filepath, MAX_PATH_LEN) < 0) {
//         send_error(c->fd, 403, "Forbidden");
//         close_conn(epfd, c); return;
//     }

//     // fprintf(stdout, "[%s] %s %s -> %s\n",
//     //         date_str(), c->method, raw_url, c->filepath);

//     /* ── Upload ── */
//     if (is_upload) {
//         const char *cl = strcasestr(hdrs, "Content-Length:");
//         if (cl) c->upload_expected = atoll(cl + 15);
//         if (c->upload_expected > MAX_UPLOAD_SIZE) {
//             send_error(c->fd, 413, "Payload Too Large");
//             close_conn(epfd, c); return;
//         }
//         mkdir(UPLOAD_DIR, 0755);
//         c->upload_fd = open(c->filepath,
//                             O_CREAT|O_WRONLY|O_TRUNC|O_NONBLOCK, 0644);
//         if (c->upload_fd < 0) {
//             send_error(c->fd, 500, "Internal Server Error");
//             close_conn(epfd, c); return;
//         }
//         const char *body = eoh + 4;
//         int avail = (int)(c->hdr_buf + c->hdr_len - body);
//         if (avail > 0) {
//             ssize_t w = write(c->upload_fd, body, avail);
//             if (w > 0) c->upload_received += w;
//         }
//         if (c->upload_expected > 0 && c->upload_received >= c->upload_expected) {
//             close(c->upload_fd); c->upload_fd = -1;
//             send_file_headers(c, 201);
//             close_conn(epfd, c); return;
//         }
//         c->state = STATE_RECEIVING_UPLOAD;
//         /* Stay on EPOLLIN */
//         return;
//     }

//     /* ── GET / HEAD ── */
//     if (strcasecmp(c->method,"GET") != 0 && strcasecmp(c->method,"HEAD") != 0) {
//         send_error(c->fd, 405, "Method Not Allowed");
//         close_conn(epfd, c); return;
//     }

//     int ffd = open(c->filepath, O_RDONLY);
//     if (ffd < 0) {
//         send_error(c->fd, 404, "Not Found");
//         close_conn(epfd, c); return;
//     }
//     struct stat st;
//     if (fstat(ffd, &st) < 0 || !S_ISREG(st.st_mode)) {
//         close(ffd);
//         send_error(c->fd, 403, "Forbidden");
//         close_conn(epfd, c); return;
//     }
//     c->file_fd   = ffd;
//     c->file_size = st.st_size;

//     int rr = parse_range(hdrs, c->file_size, &c->range_start, &c->range_end);
//     if (rr == -2) {
//         char buf[128];
//         int n = snprintf(buf, sizeof(buf),
//             "HTTP/1.1 416 Range Not Satisfiable\r\n"
//             "Content-Range: bytes */%lld\r\nContent-Length: 0\r\n"
//             "Connection: close\r\n\r\n", (long long)c->file_size);
//         send(c->fd, buf, n, MSG_NOSIGNAL);
//         close_conn(epfd, c); return;
//     } else if (rr == 0) {
//         c->is_range      = 1;
//         c->file_offset   = c->range_start;
//         c->bytes_to_send = c->range_end - c->range_start + 1;
//         send_file_headers(c, 206);
//     } else {
//         c->file_offset   = 0;
//         c->bytes_to_send = st.st_size;
//         send_file_headers(c, 200);
//     }

//     if (strcasecmp(c->method,"HEAD") == 0) {
//         close_conn(epfd, c); return;
//     }

//     c->state = STATE_SENDING_FILE;
//     watch_write(epfd, c);
// }

// /* ─────────────────────────────────────────────────────────────────
//  * handle_read
//  *
//  * KEY RULE for edge-triggered epoll: you must keep calling recv()
//  * until it returns EAGAIN, otherwise the fd won't fire again even
//  * though data is waiting.  A single recv() per event is the #1
//  * cause of connection stalls under high concurrency.
//  * ───────────────────────────────────────────────────────────────── */
// static void handle_read(int epfd, struct conn *c)
// {
//     for (;;) {
//         if (c->state == STATE_RECEIVING_UPLOAD) {
//             char buf[READ_SZ];
//             ssize_t n = recv(c->fd, buf, sizeof(buf), 0);
//             if (n == 0) { close_conn(epfd, c); return; }
//             if (n < 0) {
//                 if (errno == EAGAIN || errno == EWOULDBLOCK) return;
//                 close_conn(epfd, c); return;
//             }
//             if (c->upload_received + n > MAX_UPLOAD_SIZE) {
//                 send_error(c->fd, 413, "Payload Too Large");
//                 close_conn(epfd, c); return;
//             }
//             ssize_t w = write(c->upload_fd, buf, n);
//             if (w > 0) c->upload_received += w;
//             if (c->upload_expected > 0 && c->upload_received >= c->upload_expected) {
//                 close(c->upload_fd); c->upload_fd = -1;
//                 send_file_headers(c, 201);
//                 close_conn(epfd, c);
//             }
//             return; /* next recv on next EPOLLIN */
//         }

//         /* Reading request headers */
//         int room = HEADER_BUF_SZ - c->hdr_len - 1;
//         if (room <= 0) {
//             send_error(c->fd, 431, "Request Header Fields Too Large");
//             close_conn(epfd, c); return;
//         }
//         ssize_t n = recv(c->fd, c->hdr_buf + c->hdr_len, room, 0);
//         if (n == 0) { close_conn(epfd, c); return; }
//         if (n < 0) {
//             if (errno == EAGAIN || errno == EWOULDBLOCK) return; /* fully drained */
//             close_conn(epfd, c); return;
//         }
//         c->hdr_len += n;
//         c->hdr_buf[c->hdr_len] = '\0';

//         if (!strstr(c->hdr_buf, "\r\n\r\n")) continue; /* need more data */

//         process_headers(epfd, c);
//         return; /* process_headers takes over; stop the read loop */
//     }
// }

// /* ─────────────────────────────────────────────────────────────────
//  * handle_write
//  *
//  * Same rule: drain until EAGAIN.  When the socket buffer fills we
//  * save our position in c->file_offset / c->bytes_to_send and
//  * return – epoll will call us again when space is available.
//  * ───────────────────────────────────────────────────────────────── */
// static void handle_write(int epfd, struct conn *c)
// {
//     if (c->state != STATE_SENDING_FILE) return;

//     char chunk[READ_SZ];
//     while (c->bytes_to_send > 0) {
//         size_t want = (size_t)c->bytes_to_send < sizeof(chunk)
//                     ? (size_t)c->bytes_to_send : sizeof(chunk);
//         ssize_t r = pread(c->file_fd, chunk, want, c->file_offset);
//         if (r <= 0) { close_conn(epfd, c); return; }

//         ssize_t sent = 0;
//         while (sent < r) {
//             ssize_t s = send(c->fd, chunk + sent, (size_t)(r - sent), MSG_NOSIGNAL);
//             if (s < 0) {
//                 // if (errno == EAGAIN || errno == EWOULDBLOCK) {
//                     /* Socket buffer full; save progress, wait for next EPOLLOUT */
//                     // c->file_offset   += sent;
//                     // c->bytes_to_send -= sent;
//                     // return;
//                 // }
//                 if (errno == EAGAIN || errno == EWOULDBLOCK) {
//                     c->file_offset   += sent;
//                     c->bytes_to_send -= sent;
//                     watch_write(epfd, c);  // re-arm EPOLLOUT
//                     return;
//                 }
//                 close_conn(epfd, c); return;
//             }
//             sent += s;
//         }
//         c->file_offset   += r;
//         c->bytes_to_send -= r;
//     }
//     close(c->file_fd);
//     c->file_fd       = -1;
//     c->bytes_to_send = 0;
//     c->file_offset   = 0;
//     c->is_range      = 0;
//     c->range_start   = 0;
//     c->range_end     = 0;
//     memset(c->hdr_buf, 0, c->hdr_len + 1);
//     c->hdr_len       = 0;
//     c->state         = STATE_READING_HEADERS;

//     struct epoll_event ev = { .events = EPOLLIN | EPOLLET, .data.ptr = c };
//     epoll_ctl(epfd, EPOLL_CTL_MOD, c->fd, &ev);
//     // handle_read(epfd, c);  // <-- add this line
// }

// /* ── Event loop ───────────────────────────────────────────────── */

// static void server_loop(int server_sock)
// {
//     int epfd = epoll_create1(0);
//     if (epfd < 0) fatal("epoll_create1");

//     {
//         struct epoll_event ev = { .events = EPOLLIN | EPOLLET, .data.fd = server_sock };
//         epoll_ctl(epfd, EPOLL_CTL_ADD, server_sock, &ev);
//     }

//     struct epoll_event events[MAX_EVENTS];

//     for (;;) {
//         int nfds = epoll_wait(epfd, events, MAX_EVENTS, -1);
//         if (nfds < 0) { if (errno == EINTR) continue; fatal("epoll_wait"); }

//         for (int i = 0; i < nfds; i++) {
//             /* ── New connection(s) ── */
//             if (events[i].data.fd == server_sock) {
//                 /*
//                  * Server socket is edge-triggered too: drain ALL pending
//                  * accept()s in one shot or we'll miss connections until
//                  * the next new arrival.
//                  */
//                 for (;;) {
//                     int cfd = accept(server_sock, NULL, NULL);
//                     if (cfd < 0) {
//                         if (errno == EAGAIN || errno == EWOULDBLOCK) break;
//                         perror("accept"); break;
//                     }
//                     set_nonblocking(cfd);

//                     struct conn *c = calloc(1, sizeof(*c));
//                     if (!c) { close(cfd); continue; }
//                     c->fd        = cfd;
//                     c->file_fd   = -1;
//                     c->upload_fd = -1;
//                     c->state     = STATE_READING_HEADERS;

//                     struct epoll_event ev = {
//                         .events   = EPOLLIN | EPOLLET,
//                         .data.ptr = c
//                     };
//                     epoll_ctl(epfd, EPOLL_CTL_ADD, cfd, &ev);
//                 }
//                 continue;
//             }

//             struct conn *c = events[i].data.ptr;

//             if (events[i].events & (EPOLLERR | EPOLLHUP)) {
//                 close_conn(epfd, c); continue;
//             }
//             if (events[i].events & EPOLLIN)  handle_read (epfd, c);
//             if (events[i].events & EPOLLOUT) handle_write(epfd, c);
//         }
//     }
// }

// /* ── Setup ────────────────────────────────────────────────────── */

// static int setup_listening_socket(int port)
// {
//     int sock = socket(AF_INET, SOCK_STREAM, 0);
//     if (sock < 0) fatal("socket");
//     int on = 1;
//     setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
//     set_nonblocking(sock);   /* required: we drain accept() in a loop */
//     struct sockaddr_in addr = {
//         .sin_family      = AF_INET,
//         .sin_port        = htons(port),
//         .sin_addr.s_addr = INADDR_ANY
//     };
//     if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) fatal("bind");
//     if (listen(sock, 4096) < 0) fatal("listen");
//     return sock;
// }

// int main(int argc, char *argv[])
// {
//     signal(SIGPIPE, SIG_IGN);
//     mkdir(UPLOAD_DIR, 0755);

//     int port = (argc > 1) ? atoi(argv[1]) : 8000;
//     int server_sock = setup_listening_socket(port);
//     printf("EpollServer listening on port %d\n", port);
//     server_loop(server_sock);
//     return 0;
// }

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

                // 1. Better Parsing: Extract method and raw URL separately
                char raw_url[MAX_PATH_LEN] = {0};
                // buf looks like: "GET /index.html HTTP/1.1"
                if (sscanf(buf, "%s %s", req->method, raw_url) < 2) {
                    // Fallback if the request is malformed
                    snprintf(req->filepath, MAX_PATH_LEN, "../public/index.html");
                } else {
                    // 2. Map the URL to the physical location shown in your screenshot
                    if (strcmp(raw_url, "/") == 0) {
                        snprintf(req->filepath, MAX_PATH_LEN, "../public/index.html");
                    } else {
                        // Prepend ../public/ to whatever they asked for
                        // Example: /tux.png becomes ../public/tux.png
                        snprintf(req->filepath, MAX_PATH_LEN, "../public%s", raw_url);
                    }
                }

                // 3. LOGGING: This is vital. Add this to see what's happening!
                printf("[%s] %s %s -> Local: %s\n", get_date_string(), req->method, raw_url, req->filepath);

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