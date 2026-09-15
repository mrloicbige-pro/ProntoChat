#ifndef CHAT_SERVER_USERS_H
#define CHAT_SERVER_USERS_H

#include <stddef.h>

#include <sodium.h>

#include "common/protocole.h"

#define CHAT_SERVER_MAX_USERS 256u

struct lws;

typedef enum {
    CHAT_SERVER_USERS_OK = 0,
    CHAT_SERVER_USERS_ERR_INVALID = -1,
    CHAT_SERVER_USERS_ERR_FULL = -2,
    CHAT_SERVER_USERS_ERR_EXISTS = -3,
    CHAT_SERVER_USERS_ERR_NOT_FOUND = -4
} chat_server_users_result_t;

typedef struct {
    char username[CHAT_USERNAME_MAX_LEN + 1u];
    unsigned char identity_pk[crypto_sign_PUBLICKEYBYTES];
    struct lws *wsi;
    void *session;
    int online;
} chat_server_user_t;

typedef struct {
    chat_server_user_t users[CHAT_SERVER_MAX_USERS];
    size_t count;
} chat_server_users_t;

void chat_server_users_init(chat_server_users_t *registry);
chat_server_users_result_t chat_server_users_register(
    chat_server_users_t *registry,
    const char *username,
    const unsigned char identity_pk[crypto_sign_PUBLICKEYBYTES]);
const chat_server_user_t *chat_server_users_find(const chat_server_users_t *registry,
                                                 const char *username);
chat_server_user_t *chat_server_users_find_mut(chat_server_users_t *registry,
                                               const char *username);
chat_server_users_result_t chat_server_users_set_online(chat_server_users_t *registry,
                                                        const char *username,
                                                        struct lws *wsi,
                                                        void *session);
void chat_server_users_set_offline_by_wsi(chat_server_users_t *registry, struct lws *wsi);
const char *chat_server_users_result_name(chat_server_users_result_t result);

#endif
