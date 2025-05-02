#include "../include/logger.h"

// 日志文件指针
static FILE *error_log = NULL;
static FILE *access_log = NULL;

int init_logger(const char *error_log_path, const char *access_log_path) {
    // 以追加模式打开日志文件
    error_log = fopen(error_log_path, "a");
    access_log = fopen(access_log_path, "a");
    
    // 检查文件是否成功打开
    if (!error_log || !access_log) {
        if (error_log) fclose(error_log);
        if (access_log) fclose(access_log);
        return -1;
    }
    
    return 0;
}

void close_logger(void) {
    // 关闭日志文件
    if (error_log) fclose(error_log);
    if (access_log) fclose(access_log);
}

void log_error(const char *format, ...) {
    if (!error_log) return;
    
    // 获取当前时间
    time_t now;
    char time_buf[128];
    va_list args;
    
    time(&now);
    strftime(time_buf, sizeof(time_buf), "[%a %b %d %H:%M:%S %Y]", localtime(&now));
    
    // 写入时间戳和错误信息
    fprintf(error_log, "%s ", time_buf);
    va_start(args, format);
    vfprintf(error_log, format, args);
    va_end(args);
    // 立即刷新缓冲区
    fflush(error_log);
}

void log_access(const char *client_ip, const char *request_line, int status_code, int bytes_sent) {
    if (!access_log) return;
    
    // 获取当前时间
    time_t now;
    char time_buf[128];
    
    time(&now);
    strftime(time_buf, sizeof(time_buf), "[%d/%b/%Y:%H:%M:%S %z]", localtime(&now));
    
    // 写入访问日志（Apache格式）
    fprintf(access_log, "%s - - %s \"%s\" %d %d\n",
            client_ip, time_buf, request_line, status_code, bytes_sent);
    // 立即刷新缓冲区
    fflush(access_log);
} 