#ifndef CHAT_IDENTITY_H
#define CHAT_IDENTITY_H

#include <stddef.h>

#include <sodium.h>

#include "common/protocole.h"

#define CHAT_CONFIG_DIR_ENV "CHAT_CONFIG_DIR"
#define CHAT_IDENTITY_FINGERPRINT_LEN (crypto_generichash_BYTES * 3u)
#define CHAT_IDENTITY_SERVER_URL_MAX 256u

typedef enum {
    CHAT_IDENTITY_OK = 0,
    CHAT_IDENTITY_ERR_INVALID_USERNAME = -1,
    CHAT_IDENTITY_ERR_ALREADY_EXISTS = -2,
    CHAT_IDENTITY_ERR_SODIUM = -3,
    CHAT_IDENTITY_ERR_IO = -4,
    CHAT_IDENTITY_ERR_BUFFER = -5,
    CHAT_IDENTITY_ERR_NOT_FOUND = -6,
    CHAT_IDENTITY_ERR_BAD_FILE = -7
} chat_identity_result_t;

typedef struct {
    char username[CHAT_USERNAME_MAX_LEN + 1u];
    unsigned char public_key[crypto_sign_PUBLICKEYBYTES];
    unsigned char secret_key[crypto_sign_SECRETKEYBYTES];
} chat_identity_t;

const char *chat_identity_result_name(chat_identity_result_t result);

chat_identity_result_t chat_identity_config_dir(char *out, size_t out_size);
chat_identity_result_t chat_identity_create(const char *username,
                                            chat_identity_t *out_identity,
                                            char *fingerprint_out,
                                            size_t fingerprint_out_size);
chat_identity_result_t chat_identity_load(chat_identity_t *out_identity);
chat_identity_result_t chat_identity_load_server_url(char *out, size_t out_size);
void chat_identity_wipe(chat_identity_t *identity);

chat_identity_result_t chat_identity_fingerprint(
    const unsigned char public_key[crypto_sign_PUBLICKEYBYTES],
    char *out,
    size_t out_size);

#endif
