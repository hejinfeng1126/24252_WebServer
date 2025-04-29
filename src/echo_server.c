#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>
#include "../include/parse.h"
#include <asm-generic/socket.h>

#define ECHO_PORT 9999
#define BUF_SIZE 4096
#define MAX_HEADER_SIZE 8192
#define LOG_BUF_SIZE 1024

// 响应消息定义
#define RESPONSE_200 "HTTP/1.1 200 OK\r\n"
#define RESPONSE_400 "HTTP/1.1 400 Bad request\r\n\r\n"
#define RESPONSE_404 "HTTP/1.1 404 Not Found\r\n\r\n"
#define RESPONSE_501 "HTTP/1.1 501 Not Implemented\r\n\r\n"
#define RESPONSE_505 "HTTP/1.1 505 HTTP Version not supported\r\n\r\n"

// MIME类型
struct mime_type {
    const char *extension;
    const char *type;
} mime_types[] = {
    {".html", "text/html"},
    {".css", "text/css"},
    {".png", "image/png"},
    {".jpg", "image/jpeg"},
    {".jpeg", "image/jpeg"},
    {".gif", "image/gif"},
    {NULL, NULL}
};

FILE *error_log;
FILE *access_log;

void log_error(const char *format, ...) {
    time_t now;
    char time_buf[128];
    va_list args;
    
    time(&now);
    strftime(time_buf, sizeof(time_buf), "[%a %b %d %H:%M:%S %Y]", localtime(&now));
    
    fprintf(error_log, "%s ", time_buf);
    va_start(args, format);
    vfprintf(error_log, format, args);
    va_end(args);
    fflush(error_log);
}

void log_access(const char *client_ip, const char *request_line, int status_code, int bytes_sent) {
    time_t now;
    char time_buf[128];
    
    time(&now);
    strftime(time_buf, sizeof(time_buf), "[%d/%b/%Y:%H:%M:%S %z]", localtime(&now));
    
    fprintf(access_log, "%s - - %s \"%s\" %d %d\n",
            client_ip, time_buf, request_line, status_code, bytes_sent);
    fflush(access_log);
}

const char* get_mime_type(const char *filename) {
    const char *dot = strrchr(filename, '.');
    if (!dot) return "text/plain";
    
    for (int i = 0; mime_types[i].extension != NULL; i++) {
        if (strcasecmp(dot, mime_types[i].extension) == 0) {
            return mime_types[i].type;
        }
    }
    return "text/plain";
}

int sock = -1, client_sock = -1;
char buf[BUF_SIZE];
char response[BUF_SIZE];

int close_socket(int sock) {
    if (close(sock)) {
        fprintf(stderr, "Failed closing socket.\n");
        return 1;
    }
    return 0;
}

void handle_signal(const int sig) {
    if (sock != -1) {
        fprintf(stderr, "\nReceived signal %d. Closing socket.\n", sig);
        close_socket(sock);
    }
    exit(0);
}

void handle_http_request(int client_sock, char *request_buf, size_t request_len) {
    Request *request = parse(request_buf, request_len, client_sock);
    
    if (!request) {
        // Parse failed - send 400 Bad Request
        const char *error_response = "HTTP/1.1 400 Bad Request\r\n\r\n";
        send(client_sock, error_response, strlen(error_response), 0);
        return;
    }

    // Check HTTP method
    if (strcmp(request->http_method, "GET") == 0 ||
        strcmp(request->http_method, "POST") == 0) {
        // For GET and POST, echo back the request with proper headers
        snprintf(response, BUF_SIZE,
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: %zu\r\n"
                "\r\n"
                "%s",
                request_len, request_buf);
        send(client_sock, response, strlen(response), 0);
    }
    else if (strcmp(request->http_method, "HEAD") == 0) {
        // For HEAD, only send headers
        const char *head_response = 
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: 0\r\n"
            "\r\n";
        send(client_sock, head_response, strlen(head_response), 0);
    }
    else {
        // For unsupported methods, return 501
        const char *error_response = "HTTP/1.1 501 Not Implemented\r\n\r\n";
        send(client_sock, error_response, strlen(error_response), 0);
    }

    free(request->headers);
    free(request);
}

int main(int argc, char *argv[]) {
    signal(SIGTERM, handle_signal);
    signal(SIGINT, handle_signal);
    signal(SIGSEGV, handle_signal);
    signal(SIGABRT, handle_signal);
    signal(SIGQUIT, handle_signal);
    signal(SIGTSTP, handle_signal);

    socklen_t cli_size;
    struct sockaddr_in addr, cli_addr;
    fprintf(stdout, "----- Echo HTTP Server -----\n");

    if ((sock = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
        fprintf(stderr, "Failed creating socket.\n");
        return EXIT_FAILURE;
    }

    int opt = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        fprintf(stderr, "Failed setting socket options.\n");
        return EXIT_FAILURE;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(ECHO_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr *) &addr, sizeof(addr))) {
        close_socket(sock);
        fprintf(stderr, "Failed binding socket.\n");
        return EXIT_FAILURE;
    }

    if (listen(sock, 5)) {
        close_socket(sock);
        fprintf(stderr, "Error listening on socket.\n");
        return EXIT_FAILURE;
    }

    fprintf(stdout, "Server listening on port %d...\n", ECHO_PORT);

    while (1) {
        cli_size = sizeof(cli_addr);
        client_sock = accept(sock, (struct sockaddr *) &cli_addr, &cli_size);

        if (client_sock == -1) {
            fprintf(stderr, "Error accepting connection.\n");
            continue;
        }

        fprintf(stdout, "New connection from %s:%d\n",
                inet_ntoa(cli_addr.sin_addr),
                ntohs(cli_addr.sin_port));

        // Set receive timeout
        struct timeval tv;
        tv.tv_sec = 5;  // 5 seconds timeout
        tv.tv_usec = 0;
        setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

        memset(buf, 0, BUF_SIZE);
        int readret = recv(client_sock, buf, BUF_SIZE, 0);

        if (readret > 0) {
            fprintf(stdout, "Received request:\n%s\n", buf);
            handle_http_request(client_sock, buf, readret);
        }
        else if (readret == 0) {
            fprintf(stdout, "Client closed connection.\n");
        }
        else {
            fprintf(stderr, "Error receiving data.\n");
        }

        close_socket(client_sock);
    }

    close_socket(sock);
    return EXIT_SUCCESS;
}
