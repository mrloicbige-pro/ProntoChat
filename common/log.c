#include "common/log.h"

#include <stdarg.h>
#include <stdio.h>

static chat_log_level_t g_chat_log_level = CHAT_LOG_INFO;

static const char *chat_log_level_name(chat_log_level_t level)
{
    switch (level) {
    case CHAT_LOG_ERROR:
        return "ERROR";
    case CHAT_LOG_WARN:
        return "WARN";
    case CHAT_LOG_INFO:
        return "INFO";
    case CHAT_LOG_DEBUG:
        return "DEBUG";
    case CHAT_LOG_TRACE:
        return "TRACE";
    }

    return "UNKNOWN";
}

void chat_log_set_level(chat_log_level_t level)
{
    g_chat_log_level = level;
}

chat_log_level_t chat_log_get_level(void)
{
    return g_chat_log_level;
}

void chat_log(chat_log_level_t level, const char *fmt, ...)
{
    if (level > g_chat_log_level) {
        return;
    }

    FILE *stream = level <= CHAT_LOG_WARN ? stderr : stdout;
    fprintf(stream, "%s: ", chat_log_level_name(level));

    va_list args;
    va_start(args, fmt);
    vfprintf(stream, fmt, args);
    va_end(args);

    fputc('\n', stream);
}
