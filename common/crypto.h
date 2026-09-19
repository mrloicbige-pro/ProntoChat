#ifndef CHAT_CRYPTO_H
#define CHAT_CRYPTO_H

#include <stddef.h>

#include <sodium.h>

#include "common/identity.h"

#define CHAT_CRYPTO_SESSION_ID_MAX 128u
#define CHAT_CRYPTO_KX_MESSAGE_BYTES (crypto_kx_PUBLICKEYBYTES + crypto_sign_BYTES)
#define CHAT_CRYPTO_STREAM_HEADER_BYTES crypto_secretstream_xchacha20poly1305_HEADERBYTES
#define CHAT_CRYPTO_STREAM_ABYTES crypto_secretstream_xchacha20poly1305_ABYTES

typedef enum {
    CHAT_CRYPTO_OK = 0,
    CHAT_CRYPTO_ERR_NULL = -1,
    CHAT_CRYPTO_ERR_INVALID = -2,
    CHAT_CRYPTO_ERR_BUFFER = -3,
    CHAT_CRYPTO_ERR_SODIUM = -4,
    CHAT_CRYPTO_ERR_VERIFY = -5,
    CHAT_CRYPTO_ERR_DECRYPT = -6,
    CHAT_CRYPTO_ERR_TOO_LARGE = -7
} chat_crypto_result_t;

typedef enum {
    CHAT_CRYPTO_ROLE_INITIATOR = 1,
    CHAT_CRYPTO_ROLE_RESPONDER = 2
} chat_crypto_role_t;

typedef struct {
    unsigned char rx[crypto_kx_SESSIONKEYBYTES];
    unsigned char tx[crypto_kx_SESSIONKEYBYTES];
} chat_crypto_session_keys_t;

typedef struct {
    chat_crypto_role_t role;
    unsigned char local_identity_pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char remote_identity_pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char local_kx_pk[crypto_kx_PUBLICKEYBYTES];
    unsigned char local_kx_sk[crypto_kx_SECRETKEYBYTES];
    unsigned char session_id[CHAT_CRYPTO_SESSION_ID_MAX];
    size_t session_id_len;
    int initialized;
    int finished;
} chat_crypto_handshake_t;

typedef struct {
    crypto_secretstream_xchacha20poly1305_state push;
    crypto_secretstream_xchacha20poly1305_state pull;
    int push_initialized;
    int pull_initialized;
} chat_crypto_secretstream_t;

const char *chat_crypto_result_name(chat_crypto_result_t result);

chat_crypto_result_t chat_crypto_handshake_init(
    chat_crypto_handshake_t *handshake,
    const chat_identity_t *identity,
    const unsigned char remote_identity_pk[crypto_sign_PUBLICKEYBYTES],
    chat_crypto_role_t role,
    const unsigned char *session_id,
    size_t session_id_len,
    unsigned char out_message[CHAT_CRYPTO_KX_MESSAGE_BYTES]);

chat_crypto_result_t chat_crypto_handshake_finish(
    chat_crypto_handshake_t *handshake,
    const unsigned char remote_message[CHAT_CRYPTO_KX_MESSAGE_BYTES],
    chat_crypto_session_keys_t *out_keys);

void chat_crypto_handshake_wipe(chat_crypto_handshake_t *handshake);
void chat_crypto_session_keys_wipe(chat_crypto_session_keys_t *keys);

void chat_crypto_secretstream_init(chat_crypto_secretstream_t *stream);
chat_crypto_result_t chat_crypto_secretstream_init_push(
    chat_crypto_secretstream_t *stream,
    const unsigned char tx_key[crypto_kx_SESSIONKEYBYTES],
    unsigned char out_header[CHAT_CRYPTO_STREAM_HEADER_BYTES]);
chat_crypto_result_t chat_crypto_secretstream_init_pull(
    chat_crypto_secretstream_t *stream,
    const unsigned char rx_key[crypto_kx_SESSIONKEYBYTES],
    const unsigned char header[CHAT_CRYPTO_STREAM_HEADER_BYTES]);
chat_crypto_result_t chat_crypto_secretstream_encrypt(
    chat_crypto_secretstream_t *stream,
    const unsigned char *plaintext,
    size_t plaintext_len,
    int final,
    unsigned char *ciphertext,
    size_t ciphertext_size,
    size_t *out_ciphertext_len);
chat_crypto_result_t chat_crypto_secretstream_decrypt(
    chat_crypto_secretstream_t *stream,
    const unsigned char *ciphertext,
    size_t ciphertext_len,
    unsigned char *plaintext,
    size_t plaintext_size,
    size_t *out_plaintext_len,
    unsigned char *out_tag);
void chat_crypto_secretstream_wipe(chat_crypto_secretstream_t *stream);

#endif
