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

chat_server_users_result_t chat_server_users_register(
    chat_server_users_t *registry,
    const char *username,
    const unsigned char identity_pk[crypto_sign_PUBLICKEYBYTES])
{
    if (registry == NULL || identity_pk == NULL || !chat_username_is_valid(username)) {
        return CHAT_SERVER_USERS_ERR_INVALID;
    }

    if (registry->count >= CHAT_SERVER_MAX_USERS) {
        return CHAT_SERVER_USERS_ERR_FULL;
    }

    if (chat_server_users_find(registry, username) != NULL) {
        return CHAT_SERVER_USERS_ERR_EXISTS;
    }

    chat_server_user_t *user = &registry->users[registry->count++];
    (void)snprintf(user->username, sizeof(user->username), "%s", username);
    memcpy(user->identity_pk, identity_pk, crypto_sign_PUBLICKEYBYTES);
    user->wsi = NULL;
    user->session = NULL;
    user->online = 0;

    return CHAT_SERVER_USERS_OK;
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

chat_server_user_t *chat_server_users_find_mut(chat_server_users_t *registry,
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

chat_server_users_result_t chat_server_users_set_online(chat_server_users_t *registry,
                                                        const char *username,
                                                        struct lws *wsi,
                                                        void *session)
{
    chat_server_user_t *user = chat_server_users_find_mut(registry, username);
    if (user == NULL) {
        return CHAT_SERVER_USERS_ERR_NOT_FOUND;
    }

    user->online = 1;
    user->wsi = wsi;
    user->session = session;
    return CHAT_SERVER_USERS_OK;
}

void chat_server_users_set_offline_by_wsi(chat_server_users_t *registry, struct lws *wsi)
{
    if (registry == NULL || wsi == NULL) {
        return;
    }

    for (size_t i = 0; i < registry->count; ++i) {
        if (registry->users[i].wsi == wsi) {
            registry->users[i].online = 0;
            registry->users[i].wsi = NULL;
            registry->users[i].session = NULL;
        }
    }
}

const char *chat_server_users_result_name(chat_server_users_result_t result)
{
    switch (result) {
    case CHAT_SERVER_USERS_OK:
        return "ok";
    case CHAT_SERVER_USERS_ERR_INVALID:
        return "invalid user";
    case CHAT_SERVER_USERS_ERR_FULL:
        return "user registry full";
    case CHAT_SERVER_USERS_ERR_EXISTS:
        return "user already exists";
    case CHAT_SERVER_USERS_ERR_NOT_FOUND:
        return "user not found";
    }

    return "unknown users error";
}
