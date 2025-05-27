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

/* 服务器配置常量 */
#define ECHO_PORT 9999
#define BUF_SIZE 4096
#define GET_SUCCESS 1
#define GET_FAILURE 0
#define URL_MAX_SIZE 256
#define O_RDONLY 00
#define S_ISREG 0100000
#define S_IRUSR 00400
#define MAX_CLIENT 1024  // 最大客户端连接数

/**
 * 关闭套接字连接
 * @param sock 待关闭的套接字描述符
 * @return 0表示成功，1表示失败
 */
int close_socket(int sock)
{
    if (close(sock))
    {
        fprintf(stderr, "Failed closing socket.\n");
        return 1;
    }
    return 0;
}

/* HTTP方法常量 */
char c_get[50] = "GET";
char c_post[50] = "POST";
char c_head[50] = "HEAD";

/* HTTP响应状态行 */
char RESPONSE_400[50] = "HTTP/1.1 400 Bad request\r\n\r\n";
char RESPONSE_404[50] = "HTTP/1.1 404 Not Found\r\n\r\n";
char RESPONSE_501[50] = "HTTP/1.1 501 Not Implemented\r\n\r\n";
char RESPONSE_505[50] = "HTTP/1.1 505 HTTP Version not supported\r\n\r\n";
char RESPONSE_200[50] = "HTTP/1.1 200 OK\r\n\r\n";

/* HTTP协议与文件路径设置 */
char http_version_now[50] = "HTTP/1.1";
char root_path[50] = "./static_site";
char file_path[50] = "/index.html";

/* HTTP报文分隔标记 */
char *separate = "\r\n\r\n";

/**
 * 处理GET请求 - 读取并返回指定文件内容
 * @param request HTTP请求结构
 * @param URL 请求的资源路径
 * @param client_sock 客户端套接字
 * @param readret 读取的字节数
 * @param sock 服务器套接字
 * @return GET_SUCCESS成功，GET_FAILURE失败
 */
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

/**
 * 处理HEAD请求 - 返回HTTP头信息但不返回文件内容
 * @param requeset HTTP请求结构
 * @param URL 请求的资源路径
 * @param client_sock 客户端套接字
 * @param readret 读取的字节数
 * @param sock 服务器套接字
 * @return GET_SUCCESS成功，GET_FAILURE失败
 */
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

/**
 * 主函数 - HTTP服务器的入口点
 */
int main(int argc, char *argv[])
{
    // 基本变量声明
    int server_fd, client_fd;          // 服务器和客户端套接字描述符
    ssize_t bytes_read;                 // 读取的字节数
    socklen_t addr_len;                 // 地址结构长度
    struct sockaddr_in server_addr, client_addr;  // 服务器和客户端地址结构
    char input_buffer[BUF_SIZE * 10];   // 网络输入缓冲区
    char resp_buffer[BUF_SIZE];         // 响应缓冲区
    char req_buffer[BUF_SIZE];          // 请求解析缓冲区
    fprintf(stdout, "----- HTTP Server Starting -----\n");

    /* 创建服务器套接字 */
    if ((server_fd = socket(PF_INET, SOCK_STREAM, 0)) == -1)
    {
        fprintf(stderr, "Failed creating socket.\n");
        return EXIT_FAILURE;
    }

    /* 初始化服务器地址结构 */
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(ECHO_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    /* 绑定套接字到地址 */
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)))
    {
        close_socket(server_fd);
        fprintf(stderr, "Failed binding socket.\n");
        return EXIT_FAILURE;
    }

    /* 开始监听连接请求 */
    if (listen(server_fd, 5))
    {
        close_socket(server_fd);
        fprintf(stderr, "Error listening on socket.\n");
        return EXIT_FAILURE;
    }

    //并发处理数据结构
    int connection_table[MAX_CLIENT];   // 客户端连接表
    int active_connections = 0;         // 当前活动连接计数
    fd_set read_set_tmp;                // 临时读集合
    fd_set read_set_master;             // 主读集合

    int highest_fd = server_fd;         // 最高文件描述符
    FD_ZERO(&read_set_tmp);             // 初始化临时集合
    FD_ZERO(&read_set_master);          // 初始化主集合
    FD_SET(server_fd, &read_set_master); // 添加服务器套接字到主集合

    /* 初始化连接表 */
    for (int i = 0; i < MAX_CLIENT; i++)
        connection_table[i] = -1;       // -1表示空闲槽位

    //主事件循环 - 基于select的并发处理
    while (1)
    {
        // 复制主集合到临时集合（select会修改集合）
        read_set_tmp = read_set_master;
        
        // 使用select等待I/O事件
        int ready_count = select(highest_fd + 1, &read_set_tmp, NULL, NULL, NULL);
        if (ready_count < 0)
        {
        return EXIT_FAILURE;
    }
        else if (ready_count == 0)
        {
            continue;  // 超时，继续下一轮
        }
        
        /* 检查服务器套接字上是否有新连接 */
        if (FD_ISSET(server_fd, &read_set_tmp))
        {
            addr_len = sizeof(client_addr);
            // 接受新连接
            client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);
            if (client_fd < 0)
                continue;  // 接受失败，继续
                
            /* 查找空闲槽位存储新连接 */
            for (int i = 0; i < MAX_CLIENT; i++)
            {
                if (connection_table[i] == -1)
                {
                    // 找到空闲槽位，保存连接
                    connection_table[i] = client_fd;
                    // 将新连接添加到监听集合
                    FD_SET(client_fd, &read_set_master);
                    // 更新最高文件描述符
                    highest_fd = (client_fd > highest_fd) ? client_fd : highest_fd;
                    break;
                }
                if (i == MAX_CLIENT - 1)
                {
                    printf("Warning: Maximum connections reached!\n");
                }
            }
        }
        
        /* 处理现有客户端连接的数据 */
        for (int conn_idx = 0; conn_idx < MAX_CLIENT; conn_idx++)
        {
            // 跳过空闲槽位
            if (connection_table[conn_idx] < 0)
                continue;
                
            client_fd = connection_table[conn_idx];
            
            // 检查该连接是否有数据可读
            if (FD_ISSET(client_fd, &read_set_tmp))
            {
                bytes_read = 0;
                int header_len = 0;      // HTTP头部长度
                int buffer_pos = 0;      // 缓冲区处理位置
                
                // 接收客户端数据
                bytes_read = recv(client_fd, input_buffer, sizeof(input_buffer), 0);
                
                /* 处理连接关闭或错误 */
                if (bytes_read <= 0)
                {
                    // 关闭连接并从监听集合中移除
                    close_socket(client_fd);
                    FD_CLR(client_fd, &read_set_master);
                    connection_table[conn_idx] = -1;
                }
                else  // 收到有效数据
                {
                    /* 解析和处理HTTP请求 */
                    while (buffer_pos < bytes_read)
                    {
                        // 查找HTTP请求结束标记 "\r\n\r\n"
                        char *delim_pos = strstr(input_buffer + buffer_pos, separate);
                        if (delim_pos != NULL)
                        {
                            delim_pos += 3;  // 移动到结束标记末尾
                            header_len = delim_pos - (input_buffer + buffer_pos) + 1;

                            // 复制HTTP请求到解析缓冲区
                            memset(req_buffer, 0, sizeof(req_buffer));
                            memcpy(req_buffer, input_buffer + buffer_pos, header_len);
                            req_buffer[header_len] = '\0';  // 添加字符串结束符
                            
                            // 解析HTTP请求
                            Request *http_request = parse(req_buffer, header_len, client_fd);
                            buffer_pos += header_len;  // 更新缓冲区位置
                            
                            /* 处理不同的HTTP请求情况 */
                            if (http_request == NULL)  // 请求格式错误
                            {
                                memset(resp_buffer, 0, BUF_SIZE);
                                memcpy(resp_buffer, RESPONSE_400, sizeof(RESPONSE_400));
                                send(client_fd, resp_buffer, sizeof(resp_buffer), 0);
                            }
                            else if (strcmp(http_request->http_version, http_version_now) != 0)  // HTTP版本不支持
                            {
                                memset(resp_buffer, 0, BUF_SIZE);
                                memcpy(resp_buffer, RESPONSE_505, sizeof(RESPONSE_505));
                                send(client_fd, resp_buffer, sizeof(resp_buffer), 0);
                                free(http_request->headers);
                                free(http_request);
                            }
                            else if (!strcmp(http_request->http_method, c_post))  // POST请求
                            {
                                send(client_fd, input_buffer, bytes_read, 0);
                                free(http_request->headers);
                                free(http_request);
                            }
                            else if (!strcmp(http_request->http_method, c_get))   // GET请求
                            {
                                char resource_path[BUF_SIZE];
                                memset(resource_path, 0, sizeof(resource_path));
                                strcat(resource_path, root_path);
                                int status = GET_SUCCESS;
                                
                                // 处理URI路径
                                if (strcmp(http_request->http_uri, "/") == 0)  // 根路径
                                    strcat(resource_path, file_path);
                                else if (sizeof(http_request->http_uri) + sizeof(root_path) < URL_MAX_SIZE)
                                    strcat(resource_path, http_request->http_uri);
                                else  // URI路径过长
                                {
                                    status = GET_FAILURE;
                                    memset(resp_buffer, 0, sizeof(resp_buffer));
                                    memcpy(resp_buffer, RESPONSE_404, sizeof(RESPONSE_404));
                                    send(client_fd, resp_buffer, sizeof(resp_buffer), 0);
                                }
                                
                                // 处理GET请求
                                if (status == GET_SUCCESS)
                                {
                                    int result = http_get(http_request, resource_path, client_fd, bytes_read, server_fd);
                                    if (result == GET_FAILURE)  // 文件不存在或无法访问
                                    {
                                        memset(resp_buffer, 0, sizeof(resp_buffer));
                                        memcpy(resp_buffer, RESPONSE_404, sizeof(RESPONSE_404));
                                        send(client_fd, resp_buffer, sizeof(resp_buffer), 0);
                                    }
                                }
                                free(http_request->headers);
                                free(http_request);
                            }
                            else if (!strcmp(http_request->http_method, c_head))  // HEAD请求
                            {
                                char resource_path[BUF_SIZE];
                                memset(resource_path, 0, sizeof(resource_path));
                                strcat(resource_path, root_path);
                                int status = GET_SUCCESS;
                                
                                // 处理URI路径
                                if (strcmp(http_request->http_uri, "/") == 0)  // 根路径
                                    strcat(resource_path, file_path);
                                else if (sizeof(http_request->http_uri) + sizeof(root_path) < URL_MAX_SIZE)
                                    strcat(resource_path, http_request->http_uri);
                                else  // URI路径过长
                                {
                                    status = GET_FAILURE;
                                    memset(resp_buffer, 0, sizeof(resp_buffer));
                                    memcpy(resp_buffer, RESPONSE_404, sizeof(RESPONSE_404));
                                    send(client_fd, resp_buffer, sizeof(resp_buffer), 0);
                                }
                                
                                // 处理HEAD请求
                                if (status == GET_SUCCESS)
                                {
                                    int result = http_head(http_request, resource_path, client_fd, bytes_read, server_fd);
                                    if (result == GET_FAILURE)  // 文件不存在或无法访问
                                    {
                                        memset(resp_buffer, 0, sizeof(resp_buffer));
                                        memcpy(resp_buffer, RESPONSE_404, sizeof(RESPONSE_404));
                                        send(client_fd, resp_buffer, sizeof(resp_buffer), 0);
                                    }
                                }
                                free(http_request->headers);
                                free(http_request);
                            }
                            else  // 不支持的HTTP方法
                            {
                                memset(resp_buffer, 0, sizeof(resp_buffer));
                                memcpy(resp_buffer, RESPONSE_501, sizeof(RESPONSE_501));
                                send(client_fd, resp_buffer, sizeof(resp_buffer), 0);
                                free(http_request->headers);
                                free(http_request);
                            }
                        }
                        else  // 没找到HTTP请求结束标记
                        {
                break;
            }
                    }
                }
                
                /* 请求处理完成，关闭连接 */
                FD_CLR(client_fd, &read_set_master);
                connection_table[conn_idx] = -1;
                close_socket(client_fd);
            }
        }
    }

    /* 关闭服务器套接字 */
    close_socket(server_fd);
    return EXIT_SUCCESS;
}