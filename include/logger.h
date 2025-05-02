#ifndef _LOGGER_H_
#define _LOGGER_H_

#include <stdio.h>
#include <time.h>
#include <stdarg.h>
#include <string.h>

// 日志缓冲区大小
#define LOG_BUF_SIZE 1024

// 日志级别定义
typedef enum {
    LOG_ERROR,   // 错误日志
    LOG_INFO,    // 信息日志
    LOG_DEBUG    // 调试日志
} log_level_t;

// 初始化日志系统
// @param error_log_path: 错误日志文件路径
// @param access_log_path: 访问日志文件路径
// @return: 成功返回0，失败返回-1
int init_logger(const char *error_log_path, const char *access_log_path);

// 关闭日志系统，释放资源
void close_logger(void);

// 记录错误日志
// @param format: 格式化字符串
// @param ...: 可变参数
void log_error(const char *format, ...);

// 记录访问日志（Apache格式）
// @param client_ip: 客户端IP
// @param request_line: 请求行
// @param status_code: HTTP状态码
// @param bytes_sent: 发送的字节数
void log_access(const char *client_ip, const char *request_line, int status_code, int bytes_sent);

#endif /* _LOGGER_H_ */ 