#ifndef CHAT_IPC_H
#define CHAT_IPC_H

#include <stddef.h>

#define CHAT_SOCKET_PATH_ENV "CHAT_SOCKET_PATH"
#define CHAT_IPC_MAX_COMMAND 4096u
#define CHAT_IPC_MAX_RESPONSE 4096u

typedef enum {
    CHAT_IPC_OK = 0,
    CHAT_IPC_ERR_BUFFER = -1,
    CHAT_IPC_ERR_IO = -2
} chat_ipc_result_t;

const char *chat_ipc_result_name(chat_ipc_result_t result);
chat_ipc_result_t chat_ipc_socket_path(char *out, size_t out_size);

#endif
