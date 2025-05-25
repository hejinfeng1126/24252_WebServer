#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "parse.h"
#include <sys/stat.h>
#include <fcntl.h>

#define ECHO_PORT 9999
#define BUF_SIZE 4096
#define GET_SUCCESS 1
#define GET_FAILURE 0
#define URL_MAX_SIZE 256
#define O_RDONLY 00
#define S_ISREG 0100000
#define S_IRUSR 00400
#define MAX_CLIENT 1024

int close_socket(int sock)
{
    if (close(sock))
    {
        fprintf(stderr, "Failed closing socket.\n");
        return 1;
    }
    return 0;
}

char c_get[50] = "GET";
char c_post[50] = "POST";
char c_head[50] = "HEAD";

char RESPONSE_400[50] = "HTTP/1.1 400 Bad request\r\n\r\n";
char RESPONSE_404[50] = "HTTP/1.1 404 Not Found\r\n\r\n";
char RESPONSE_501[50] = "HTTP/1.1 501 Not Implemented\r\n\r\n";
char RESPONSE_505[50] = "HTTP/1.1 505 HTTP Version not supported\r\n\r\n";
char RESPONSE_200[50] = "HTTP/1.1 200 OK\r\n\r\n";

char http_version_now[50] = "HTTP/1.1";
char root_path[50] = "./static_site";
char file_path[50] = "/index.html";

char *separate = "\r\n\r\n";

int http_get(Request *request, char *URL, int client_sock, int readret, int sock)
{
    struct stat *file_state = (struct stat *)malloc(sizeof(struct stat));
    if (stat(URL, file_state) == -1)
        return GET_FAILURE;

    int fd_in = open(URL, O_RDONLY);
    if (!(S_ISREG & file_state->st_mode) || !(S_IRUSR & file_state->st_mode))
        return GET_FAILURE;

    if (fd_in < 0)
    {
        printf("Failed to open the file\n");
        return GET_FAILURE;
    }

    char response1[BUF_SIZE];
    char response2[BUF_SIZE];
    read(fd_in, response2, BUF_SIZE);
    memcpy(response1, RESPONSE_200, sizeof(response1));
    strcat(response1, response2);
    send(client_sock, response1, strlen(response1), 0);

    close(fd_in);
    free(file_state);
    return GET_SUCCESS;
}

int http_head(Request *requeset, char *URL, int client_sock, int readret, int sock)
{
    struct stat *file_state = (struct stat *)malloc(sizeof(struct stat));
    if (stat(URL, file_state) == -1)
    {
        return GET_FAILURE;
    }
    if (!(S_ISREG & file_state->st_mode) || !(S_IRUSR & file_state->st_mode))
    {
        return GET_FAILURE;
    }
    int fd_in = open(URL, O_RDONLY);
    if (fd_in < 0)
    {
        printf("Failed to open the file\n");
        return GET_FAILURE;
    }

    char response[BUF_SIZE];
    strcat(response, RESPONSE_200);

    if (send(client_sock, response, strlen(response), 0) != strlen(response))
    {
        close_socket(client_sock);
        close_socket(sock);
        fprintf(stderr, "Error sending to client1.\n");
        return GET_FAILURE;
    }
    close(fd_in);
    free(file_state);
    return GET_SUCCESS;
}

int main(int argc, char *argv[])
{
    int sock, client_sock;
    ssize_t readret;
    socklen_t cli_size;
    struct sockaddr_in addr, cli_addr;
    char buf[BUF_SIZE * 10];
    char buf1[BUF_SIZE];
    char buf2[BUF_SIZE];
    fprintf(stdout, "----- Echo Server -----\n");

    if ((sock = socket(PF_INET, SOCK_STREAM, 0)) == -1)
    {
        fprintf(stderr, "Failed creating socket.\n");
        return EXIT_FAILURE;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(ECHO_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)))
    {
        close_socket(sock);
        fprintf(stderr, "Failed binding socket.\n");
        return EXIT_FAILURE;
    }

    if (listen(sock, 5))
    {
        close_socket(sock);
        fprintf(stderr, "Error listening on socket.\n");
        return EXIT_FAILURE;
    }

    int fd_client[MAX_CLIENT];
    int client_count = 0;
    fd_set tmp_fd;
    fd_set ready_fd;

    int max_fd = sock;
    FD_ZERO(&tmp_fd);
    FD_ZERO(&ready_fd);
    FD_SET(sock, &ready_fd);

    for (int i = 0; i < MAX_CLIENT; i++)
        fd_client[i] = -1;

    while (1)
    {
        tmp_fd = ready_fd;
        int num_connect = select(max_fd + 1, &tmp_fd, NULL, NULL, NULL);
        if (num_connect < 0)
        {
            return EXIT_FAILURE;
        }
        else if (num_connect == 0)
        {
            continue;
        }
        if (FD_ISSET(sock, &tmp_fd))
        {
            cli_size = sizeof(cli_addr);
            client_sock = accept(sock, (struct sockaddr *)&cli_addr, &cli_size);
            if (client_sock < 0)
                continue;
            for (int i = 0; i < MAX_CLIENT; i++)
            {
                if (fd_client[i] == -1)
                {
                    fd_client[i] = client_sock;
                    FD_SET(client_sock, &ready_fd);
                    max_fd = (client_sock > max_fd) ? client_sock : max_fd;
                    break;
                }
                if (i == MAX_CLIENT - 1)
                {
                    printf("Clients Overflow!\n");
                }
            }
        }
        for (int i = 0; i < MAX_CLIENT; i++)
        {
            if (fd_client[i] < 0)
                continue;
            client_sock = fd_client[i];
            if (FD_ISSET(client_sock, &ready_fd))
            {
                readret = 0;
                int sizep = 0;
                int increase = 0;
                readret = recv(client_sock, buf, sizeof(buf), 0);
                if (readret <= 0)
                {
                    close_socket(client_sock);
                    FD_CLR(client_sock, &ready_fd);
                    fd_client[i] = -1;
                }
                else
                {
                    while (increase < readret)
                    {
                        char *tmp = strstr(buf + increase, separate);
                        if (tmp != NULL)
                        {
                            tmp += 3;
                            sizep = tmp - (buf + increase) + 1;

                            memset(buf2, 0, sizeof(buf2));
                            memcpy(buf2, buf + increase, sizep);
                            buf2[sizep] = '\0';
                            Request *request = parse(buf2, sizep, client_sock);
                            increase += sizep;
                            if (request == NULL)
                            {
                                memset(buf1, 0, BUF_SIZE);
                                memcpy(buf1, RESPONSE_400, sizeof(RESPONSE_400));
                                send(client_sock, buf1, sizeof(buf1), 0);
                            }
                            else if (strcmp(request->http_version, http_version_now) != 0)
                            {
                                memset(buf1, 0, BUF_SIZE);
                                memcpy(buf1, RESPONSE_505, sizeof(RESPONSE_505));
                                send(client_sock, buf1, sizeof(buf1), 0);
                                free(request->headers);
                                free(request);
                            }
                            else if (!strcmp(request->http_method, c_post))
                            {
                                send(client_sock, buf, readret, 0);
                                free(request->headers);
                                free(request);
                            }
                            else if (!strcmp(request->http_method, c_get))
                            {
                                char get_URL[BUF_SIZE];
                                memset(get_URL, 0, sizeof(get_URL));
                                strcat(get_URL, root_path);
                                int get_flag = GET_SUCCESS;
                                if (strcmp(request->http_uri, "/") == 0)
                                    strcat(get_URL, file_path);
                                else if (sizeof(request->http_uri) + sizeof(root_path) < URL_MAX_SIZE)
                                    strcat(get_URL, request->http_uri);
                                else
                                {
                                    get_flag = GET_FAILURE;
                                    memset(buf1, 0, sizeof(buf1));
                                    memcpy(buf1, RESPONSE_404, sizeof(RESPONSE_404));
                                    send(client_sock, buf1, sizeof(buf1), 0);
                                }
                                if (get_flag == GET_SUCCESS)
                                {
                                    int get_state = http_get(request, get_URL, client_sock, readret, sock);
                                    if (get_state == GET_FAILURE)
                                    {
                                        memset(buf1, 0, sizeof(buf1));
                                        memcpy(buf1, RESPONSE_404, sizeof(RESPONSE_404));
                                        send(client_sock, buf1, sizeof(buf1), 0);
                                    }
                                }
                                free(request->headers);
                                free(request);
                            }
                            else if (!strcmp(request->http_method, c_head))
                            {
                                char head_URL[BUF_SIZE];
                                memset(head_URL, 0, sizeof(head_URL));
                                strcat(head_URL, root_path);
                                int head_flag = GET_SUCCESS;
                                if (strcmp(request->http_uri, "/") == 0)
                                    strcat(head_URL, file_path);
                                else if (sizeof(request->http_uri) + sizeof(root_path) < URL_MAX_SIZE)
                                    strcat(head_URL, request->http_uri);
                                else
                                {
                                    head_flag = GET_FAILURE;
                                    memset(buf1, 0, sizeof(buf1));
                                    memcpy(buf1, RESPONSE_404, sizeof(RESPONSE_404));
                                    send(client_sock, buf1, sizeof(buf1), 0);
                                }
                                if (head_flag == GET_SUCCESS)
                                {
                                    int head_state = http_head(request, head_URL, client_sock, readret, sock);
                                    if (head_state == GET_FAILURE)
                                    {
                                        memset(buf1, 0, sizeof(buf1));
                                        memcpy(buf1, RESPONSE_404, sizeof(RESPONSE_404));
                                        send(client_sock, buf1, sizeof(buf1), 0);
                                    }
                                }
                                free(request->headers);
                                free(request);
                            }
                            else
                            {
                                memset(buf1, 0, sizeof(buf1));
                                memcpy(buf1, RESPONSE_501, sizeof(RESPONSE_501));
                                send(client_sock, buf1, sizeof(buf1), 0);
                                free(request->headers);
                                free(request);
                            }
                        }
                        else
                        {
                            break;
                        }
                    }
                }
                FD_CLR(client_sock, &ready_fd);
                fd_client[i] = -1;
                close_socket(client_sock);
            }
        }
    }

    close_socket(sock);
    return EXIT_SUCCESS;
}