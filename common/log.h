#ifndef CHAT_LOG_H
#define CHAT_LOG_H

typedef enum {
    CHAT_LOG_ERROR = 0,
    CHAT_LOG_WARN,
    CHAT_LOG_INFO,
    CHAT_LOG_DEBUG,
    CHAT_LOG_TRACE
} chat_log_level_t;

void chat_log_set_level(chat_log_level_t level);
chat_log_level_t chat_log_get_level(void);
void chat_log(chat_log_level_t level, const char *fmt, ...);

#endif
