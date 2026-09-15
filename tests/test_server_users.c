#include "server/users.h"

#include <assert.h>
#include <string.h>

static void test_register_find_and_presence(void)
{
    chat_server_users_t users;
    chat_server_users_init(&users);

    unsigned char public_key[crypto_sign_PUBLICKEYBYTES];
    memset(public_key, 7, sizeof(public_key));

    assert(chat_server_users_register(&users, "alex", public_key) == CHAT_SERVER_USERS_OK);
    assert(chat_server_users_register(&users, "alex", public_key) == CHAT_SERVER_USERS_ERR_EXISTS);
    assert(chat_server_users_register(&users, "ab", public_key) == CHAT_SERVER_USERS_ERR_INVALID);

    const chat_server_user_t *alex = chat_server_users_find(&users, "alex");
    assert(alex != NULL);
    assert(alex->online == 0);
    assert(memcmp(alex->identity_pk, public_key, sizeof(public_key)) == 0);

    struct lws *fake_wsi = (struct lws *)(void *)0x1;
    assert(chat_server_users_set_online(&users, "alex", fake_wsi) == CHAT_SERVER_USERS_OK);
    alex = chat_server_users_find(&users, "alex");
    assert(alex != NULL);
    assert(alex->online == 1);
    assert(alex->wsi == fake_wsi);

    chat_server_users_set_offline_by_wsi(&users, fake_wsi);
    alex = chat_server_users_find(&users, "alex");
    assert(alex != NULL);
    assert(alex->online == 0);
    assert(alex->wsi == NULL);
}

int main(void)
{
    test_register_find_and_presence();
    return 0;
}
