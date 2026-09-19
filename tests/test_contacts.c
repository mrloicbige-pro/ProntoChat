#define _POSIX_C_SOURCE 200809L

#include "common/contacts.h"

#include "common/identity.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static void make_temp_config_dir(char *template, size_t template_size)
{
    int written = snprintf(template, template_size, "/tmp/chat-contacts-test-XXXXXX");
    assert(written > 0);
    assert((size_t)written < template_size);
    assert(mkdtemp(template) != NULL);
    assert(setenv(CHAT_CONFIG_DIR_ENV, template, 1) == 0);
}

static void test_contacts_pin_match_and_mismatch(void)
{
    char config_dir[128];
    make_temp_config_dir(config_dir, sizeof(config_dir));

    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pk, sk);

    int is_new = 0;
    assert(chat_contacts_verify_or_pin("nathan", pk, &is_new) == CHAT_CONTACTS_OK);
    assert(is_new == 1);

    char contacts_path[256];
    int written = snprintf(contacts_path, sizeof(contacts_path), "%s/contacts.db", config_dir);
    assert(written > 0);
    assert((size_t)written < sizeof(contacts_path));

    struct stat st;
    assert(stat(contacts_path, &st) == 0);
    assert((st.st_mode & 0777) == 0600);

    is_new = 1;
    assert(chat_contacts_verify_or_pin("nathan", pk, &is_new) == CHAT_CONTACTS_OK);
    assert(is_new == 0);

    unsigned char loaded_pk[crypto_sign_PUBLICKEYBYTES];
    assert(chat_contacts_load_public_key("nathan", loaded_pk) == CHAT_CONTACTS_OK);
    assert(sodium_memcmp(loaded_pk, pk, sizeof(loaded_pk)) == 0);

    unsigned char other_pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char other_sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(other_pk, other_sk);
    assert(chat_contacts_verify_or_pin("nathan", other_pk, &is_new)
        == CHAT_CONTACTS_ERR_MISMATCH);

    sodium_memzero(sk, sizeof(sk));
    sodium_memzero(other_sk, sizeof(other_sk));
}

static void test_contacts_reject_invalid_username(void)
{
    char config_dir[128];
    make_temp_config_dir(config_dir, sizeof(config_dir));

    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pk, sk);

    assert(chat_contacts_verify_or_pin("ab", pk, NULL) == CHAT_CONTACTS_ERR_INVALID);
    assert(chat_contacts_load_public_key("ab", pk) == CHAT_CONTACTS_ERR_INVALID);
    sodium_memzero(sk, sizeof(sk));
}

static void test_contacts_load_missing_contact(void)
{
    char config_dir[128];
    make_temp_config_dir(config_dir, sizeof(config_dir));

    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    assert(chat_contacts_load_public_key("nathan", pk) == CHAT_CONTACTS_ERR_NOT_FOUND);
}

int main(void)
{
    assert(sodium_init() >= 0);
    test_contacts_pin_match_and_mismatch();
    test_contacts_reject_invalid_username();
    test_contacts_load_missing_contact();
    return 0;
}
