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
#include "../include/logger.h"

// Server configuration constants
#define ECHO_PORT 9999
#define BUF_SIZE 8192
#define RECV_BUF_SIZE 8192
#define MAX_HEADER_SIZE 8192

// HTTP response templates with simple format as required
#define RESPONSE_200 "HTTP/1.1 200 OK\r\n"
#define RESPONSE_400 "HTTP/1.1 400 Bad request\r\n\r\n"
#define RESPONSE_404 "HTTP/1.1 404 Not Found\r\n\r\n"
#define RESPONSE_501 "HTTP/1.1 501 Not Implemented\r\n\r\n"
#define RESPONSE_505 "HTTP/1.1 505 HTTP Version not supported\r\n\r\n"

// MIME types
struct mime_type {
    const char *extension;
    const char *type;
} mime_types[] = {
    {".html", "text/html"},
    {".css", "text/css"},
    {".js", "application/javascript"},
    {".jpg", "image/jpeg"},
    {".jpeg", "image/jpeg"},
    {".png", "image/png"},
    {".gif", "image/gif"},
    {NULL, "text/plain"}
};

// Global variables
int sock = -1, client_sock = -1;
char recv_buf[RECV_BUF_SIZE];
char response_buf[BUF_SIZE];

// Get the MIME type of a file
const char* get_mime_type(const char *filename) {
    const char *dot = strrchr(filename, '.');
    if (!dot) return mime_types[7].type;
    
    for (int i = 0; mime_types[i].extension != NULL; i++) {
        if (strcasecmp(dot, mime_types[i].extension) == 0) {
            return mime_types[i].type;
        }
    }
    return mime_types[7].type;
}

// Close the socket connection
int close_socket(int sock) {
    if (close(sock)) {
        log_error("Failed to close socket: %s\n", strerror(errno));
        return 1;
    }
    return 0;
}

// Signal handler
void handle_signal(const int sig) {
    if (sock != -1) {
        log_error("Received signal %d, closing socket.\n", sig);
        close_socket(sock);
    }
    close_logger();
    exit(0);
}

// Send file content
void send_file(int client_sock, const char *filepath, const char *method) {
    struct stat st;
    // Check if the file exists
    if (stat(filepath, &st) == -1) {
        log_error("File not found: %s\n", filepath);
        send(client_sock, RESPONSE_404, strlen(RESPONSE_404), 0);
        return;
    }

    // Try to open the file
    int fd = open(filepath, O_RDONLY);
    if (fd == -1) {
        log_error("Cannot open file %s: %s\n", filepath, strerror(errno));
        send(client_sock, RESPONSE_404, strlen(RESPONSE_404), 0);
        return;
    }

    // Send HTTP header
    const char *mime_type = get_mime_type(filepath);
    snprintf(response_buf, BUF_SIZE,
            "%s"
            "Content-Type: %s\r\n"
            "Content-Length: %ld\r\n"
            "Connection: keep-alive\r\n"
            "\r\n",
            RESPONSE_200, mime_type, st.st_size);
    send(client_sock, response_buf, strlen(response_buf), 0);

    // HEAD request only sends headers
    if (strcmp(method, "HEAD") == 0) {
        close(fd);
        return;
    }

    // Send file content
    ssize_t bytes_read;
    while ((bytes_read = read(fd, response_buf, BUF_SIZE)) > 0) {
        if (send(client_sock, response_buf, bytes_read, 0) < 0) {
            log_error("Error sending file: %s\n", strerror(errno));
            break;
        }
    }

    if (bytes_read == -1) {
        log_error("Error reading file: %s\n", strerror(errno));
    }

    close(fd);
}

// Check if the HTTP version is supported
int check_http_version(const char *version) {
    // Check if it's HTTP/1.1 or HTTP/1.0
    if (strcmp(version, "HTTP/1.1") == 0 || strcmp(version, "HTTP/1.0") == 0) {
        return 1;
    }
    return 0;
}

// Check if the HTTP method is supported
int is_supported_method(const char *method) {
    return (strcmp(method, "GET") == 0 || 
            strcmp(method, "HEAD") == 0 || 
            strcmp(method, "POST") == 0);
}

// Extract the method from a raw HTTP request
char* extract_method(const char *request_buf) {
    static char method[50];
    memset(method, 0, sizeof(method));
    
    // Skip leading whitespace
    while (*request_buf && (*request_buf == ' ' || *request_buf == '\t' || *request_buf == '\r' || *request_buf == '\n'))
        request_buf++;
    
    // Copy method name until space
    int i = 0;
    while (*request_buf && *request_buf != ' ' && i < sizeof(method) - 1) {
        method[i++] = *request_buf++;
    }
    method[i] = '\0';
    
    return method;
}

// Extract HTTP version from a raw HTTP request
char* extract_http_version(const char *request_buf) {
    static char version[20];
    memset(version, 0, sizeof(version));
    
    // Find the HTTP version string (e.g., "HTTP/1.1")
    const char *ptr = strstr(request_buf, "HTTP/");
    if (!ptr) {
        // Try lowercase variation
        ptr = strstr(request_buf, "http/");
    }
    
    if (ptr) {
        int i = 0;
        // Copy until whitespace or end of line
        while (*ptr && !(*ptr == ' ' || *ptr == '\r' || *ptr == '\n') && i < sizeof(version) - 1) {
            version[i++] = *ptr++;
        }
        version[i] = '\0';
    }
    
    return version;
}

// Handle HTTP request
void handle_http_request(int client_sock, char *request_buf, size_t request_len, const char *client_ip) {
    // If the request header is too large, return 400 error
    if (request_len > MAX_HEADER_SIZE) {
        log_error("Request header too large (%zu bytes)\n", request_len);
        send(client_sock, RESPONSE_400, strlen(RESPONSE_400), 0);
        log_access(client_ip, "Request header too large", 400, strlen(RESPONSE_400));
        return;
    }

    // Pre-check HTTP version before parsing
    char *version = extract_http_version(request_buf);
    if (strlen(version) > 0 && !check_http_version(version)) {
        log_error("Unsupported HTTP version detected before parsing: %s\n", version);
        send(client_sock, RESPONSE_505, strlen(RESPONSE_505), 0);
        log_access(client_ip, request_buf, 505, strlen(RESPONSE_505));
        return;
    }

    // Pre-check for unsupported methods before parsing
    char *method = extract_method(request_buf);
    if (strlen(method) > 0 && !is_supported_method(method)) {
        log_error("Unsupported HTTP method detected before parsing: %s\n", method);
        send(client_sock, RESPONSE_501, strlen(RESPONSE_501), 0);
        log_access(client_ip, request_buf, 501, strlen(RESPONSE_501));
        return;
    }

    // Parse HTTP request
    Request *request = parse(request_buf, request_len, client_sock);
    
    if (!request) {
        log_error("Failed to parse request from %s\n", client_ip);
        send(client_sock, RESPONSE_400, strlen(RESPONSE_400), 0);
        log_access(client_ip, "Invalid request", 400, strlen(RESPONSE_400));
        return;
    }

    // Check HTTP version
    if (!check_http_version(request->http_version)) {
        log_error("Unsupported HTTP version: %s\n", request->http_version);
        send(client_sock, RESPONSE_505, strlen(RESPONSE_505), 0);
        log_access(client_ip, request_buf, 505, strlen(RESPONSE_505));
        free(request->headers);
        free(request);
        return;
    }

    // Check HTTP method again after parsing
    if (!is_supported_method(request->http_method)) {
        log_error("Unsupported HTTP method: %s\n", request->http_method);
        send(client_sock, RESPONSE_501, strlen(RESPONSE_501), 0);
        log_access(client_ip, request_buf, 501, strlen(RESPONSE_501));
        free(request->headers);
        free(request);
        return;
    }

    // Handle different HTTP methods
    if (strcmp(request->http_method, "GET") == 0 ||
        strcmp(request->http_method, "HEAD") == 0) {
        
        // Build file path
        char filepath[1024] = "static_site";
        strcat(filepath, request->http_uri);
        
        // If root path, use index.html
        if (strcmp(request->http_uri, "/") == 0) {
            strcat(filepath, "index.html");
        }

        send_file(client_sock, filepath, request->http_method);
        log_access(client_ip, request_buf, 200, 0);
    }
    else if (strcmp(request->http_method, "POST") == 0) {
        // Echo back POST data
        snprintf(response_buf, BUF_SIZE,
                "%s"
                "Content-Type: text/plain\r\n"
                "Content-Length: %zu\r\n"
                "Connection: keep-alive\r\n"
                "\r\n"
                "%s",
                RESPONSE_200, request_len, request_buf);
        send(client_sock, response_buf, strlen(response_buf), 0);
        log_access(client_ip, request_buf, 200, strlen(response_buf));
    }
    else {
        // This is a fallback, should not be reached due to the check above
        log_error("Unexpected method: %s\n", request->http_method);
        send(client_sock, RESPONSE_501, strlen(RESPONSE_501), 0);
        log_access(client_ip, request_buf, 501, strlen(RESPONSE_501));
    }

    free(request->headers);
    free(request);
}

int main(int argc, char *argv[]) {
    // Set up signal handlers
    signal(SIGTERM, handle_signal);
    signal(SIGINT, handle_signal);
    signal(SIGSEGV, handle_signal);
    signal(SIGABRT, handle_signal);
    signal(SIGQUIT, handle_signal);
    signal(SIGTSTP, handle_signal);

    // Initialize logging system
    if (init_logger("error.log", "access.log") != 0) {
        fprintf(stderr, "Failed to initialize logging system\n");
        return EXIT_FAILURE;
    }

    socklen_t cli_size;
    struct sockaddr_in addr, cli_addr;
    fprintf(stdout, "----- HTTP Server Started -----\n");

    // Create socket
    if ((sock = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
        log_error("Failed to create socket: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    // Set socket options
    int opt = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        log_error("Failed to set socket options: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    // Configure server address
    addr.sin_family = AF_INET;
    addr.sin_port = htons(ECHO_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    // Bind socket
    if (bind(sock, (struct sockaddr *) &addr, sizeof(addr))) {
        log_error("Failed to bind socket: %s\n", strerror(errno));
        close_socket(sock);
        return EXIT_FAILURE;
    }

    // Start listening
    if (listen(sock, 5)) {
        log_error("Failed to listen on socket: %s\n", strerror(errno));
        close_socket(sock);
        return EXIT_FAILURE;
    }

    fprintf(stdout, "Server listening on port %d...\n", ECHO_PORT);

    // Main server loop
    while (1) {
        cli_size = sizeof(cli_addr);
        client_sock = accept(sock, (struct sockaddr *) &cli_addr, &cli_size);

        if (client_sock == -1) {
            log_error("Failed to accept connection: %s\n", strerror(errno));
            continue;
        }

        char *client_ip = inet_ntoa(cli_addr.sin_addr);
        fprintf(stdout, "New connection from %s:%d\n", client_ip, ntohs(cli_addr.sin_port));

        // Set persistent connection socket options
        struct timeval tv;
        tv.tv_sec = 5;  // 5 second timeout
        tv.tv_usec = 0;
        setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

        // Handle persistent connection
        while (1) {
            memset(recv_buf, 0, RECV_BUF_SIZE);
            int readret = recv(client_sock, recv_buf, RECV_BUF_SIZE, 0);

            if (readret > 0) {
                handle_http_request(client_sock, recv_buf, readret, client_ip);
            }
            else if (readret == 0) {
                fprintf(stdout, "Client closed connection\n");
                break;
            }
            else {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    fprintf(stdout, "Connection timeout\n");
                } else {
                    log_error("Failed to receive data: %s\n", strerror(errno));
                }
                break;
            }
        }

        close_socket(client_sock);
    }

    close_logger();
    close_socket(sock);
    return EXIT_SUCCESS;
}
