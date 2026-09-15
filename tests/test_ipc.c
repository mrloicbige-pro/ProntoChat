#define _POSIX_C_SOURCE 200809L

#include "common/ipc.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

static void test_socket_path_override(void)
{
    assert(setenv(CHAT_SOCKET_PATH_ENV, "/tmp/chat-test.sock", 1) == 0);

    char path[128];
    assert(chat_ipc_socket_path(path, sizeof(path)) == CHAT_IPC_OK);
    assert(strcmp(path, "/tmp/chat-test.sock") == 0);
}

static void test_socket_path_short_buffer(void)
{
    assert(setenv(CHAT_SOCKET_PATH_ENV, "/tmp/chat-test.sock", 1) == 0);

    char path[4];
    assert(chat_ipc_socket_path(path, sizeof(path)) == CHAT_IPC_ERR_BUFFER);
}

int main(void)
{
    test_socket_path_override();
    test_socket_path_short_buffer();
    return 0;
}
