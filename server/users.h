#ifndef CHAT_SERVER_USERS_H
#define CHAT_SERVER_USERS_H

#include <stddef.h>

#include "common/protocole.h"

#define CHAT_SERVER_MAX_USERS 256u

typedef struct {
    char username[CHAT_USERNAME_MAX_LEN + 1u];
    int online;
} chat_server_user_t;

typedef struct {
    chat_server_user_t users[CHAT_SERVER_MAX_USERS];
    size_t count;
} chat_server_users_t;

void chat_server_users_init(chat_server_users_t *registry);
int chat_server_users_add(chat_server_users_t *registry, const char *username);
const chat_server_user_t *chat_server_users_find(const chat_server_users_t *registry,
                                                 const char *username);

#endif
