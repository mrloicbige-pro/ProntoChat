#include "server/users.h"

#include <stdio.h>
#include <string.h>

void chat_server_users_init(chat_server_users_t *registry)
{
    if (registry == NULL) {
        return;
    }

    registry->count = 0;
}

int chat_server_users_add(chat_server_users_t *registry, const char *username)
{
    if (registry == NULL || !chat_username_is_valid(username)) {
        return -1;
    }

    if (registry->count >= CHAT_SERVER_MAX_USERS) {
        return -1;
    }

    if (chat_server_users_find(registry, username) != NULL) {
        return -1;
    }

    chat_server_user_t *user = &registry->users[registry->count++];
    (void)snprintf(user->username, sizeof(user->username), "%s", username);
    user->online = 0;

    return 0;
}

const chat_server_user_t *chat_server_users_find(const chat_server_users_t *registry,
                                                 const char *username)
{
    if (registry == NULL || username == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < registry->count; ++i) {
        if (strcmp(registry->users[i].username, username) == 0) {
            return &registry->users[i];
        }
    }

    return NULL;
}
