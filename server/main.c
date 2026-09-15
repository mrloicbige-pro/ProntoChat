#include "common/log.h"
#include "server/users.h"

#include <stdio.h>

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    chat_server_users_t users;
    chat_server_users_init(&users);

    chat_log(CHAT_LOG_INFO, "chat-server skeleton starting");
    printf("chat-server skeleton is ready. WebSocket control plane is not implemented yet.\n");
    return 0;
}
