#define _POSIX_C_SOURCE 200809L

#include "common/ipc.h"

#include "common/identity.h"

#include <stdio.h>
#include <stdlib.h>

const char *chat_ipc_result_name(chat_ipc_result_t result)
{
    switch (result) {
    case CHAT_IPC_OK:
        return "ok";
    case CHAT_IPC_ERR_BUFFER:
        return "buffer too small";
    case CHAT_IPC_ERR_IO:
        return "I/O error";
    }

    return "unknown IPC error";
}

chat_ipc_result_t chat_ipc_socket_path(char *out, size_t out_size)
{
    if (out == NULL || out_size == 0u) {
        return CHAT_IPC_ERR_BUFFER;
    }

    const char *override = getenv(CHAT_SOCKET_PATH_ENV);
    if (override != NULL && override[0] != '\0') {
        int written = snprintf(out, out_size, "%s", override);
        return written < 0 || (size_t)written >= out_size ? CHAT_IPC_ERR_BUFFER : CHAT_IPC_OK;
    }

    const char *runtime_dir = getenv("XDG_RUNTIME_DIR");
    if (runtime_dir != NULL && runtime_dir[0] != '\0') {
        int written = snprintf(out, out_size, "%s/chatd.sock", runtime_dir);
        return written < 0 || (size_t)written >= out_size ? CHAT_IPC_ERR_BUFFER : CHAT_IPC_OK;
    }

    char config_dir[512];
    if (chat_identity_config_dir(config_dir, sizeof(config_dir)) != CHAT_IDENTITY_OK) {
        return CHAT_IPC_ERR_IO;
    }

    int written = snprintf(out, out_size, "%s/chatd.sock", config_dir);
    return written < 0 || (size_t)written >= out_size ? CHAT_IPC_ERR_BUFFER : CHAT_IPC_OK;
}
