#include "common/crypto.h"

#include <stdint.h>
#include <string.h>

#define CHAT_CRYPTO_TRANSCRIPT_DOMAIN "ProntoChat crypto-kx v1"

static int chat_crypto_role_is_valid(chat_crypto_role_t role)
{
    return role == CHAT_CRYPTO_ROLE_INITIATOR || role == CHAT_CRYPTO_ROLE_RESPONDER;
}

static chat_crypto_role_t chat_crypto_opposite_role(chat_crypto_role_t role)
{
    return role == CHAT_CRYPTO_ROLE_INITIATOR
        ? CHAT_CRYPTO_ROLE_RESPONDER
        : CHAT_CRYPTO_ROLE_INITIATOR;
}

static void chat_crypto_write_u64_be(unsigned char out[8], uint64_t value)
{
    for (size_t i = 0u; i < 8u; ++i) {
        out[i] = (unsigned char)((value >> ((7u - i) * 8u)) & 0xffu);
    }
}

static chat_crypto_result_t chat_crypto_transcript_hash(
    chat_crypto_role_t signer_role,
    const unsigned char signer_identity_pk[crypto_sign_PUBLICKEYBYTES],
    const unsigned char peer_identity_pk[crypto_sign_PUBLICKEYBYTES],
    const unsigned char *session_id,
    size_t session_id_len,
    const unsigned char signer_kx_pk[crypto_kx_PUBLICKEYBYTES],
    unsigned char out_hash[crypto_generichash_BYTES])
{
    if (!chat_crypto_role_is_valid(signer_role)
        || signer_identity_pk == NULL
        || peer_identity_pk == NULL
        || session_id == NULL
        || signer_kx_pk == NULL
        || out_hash == NULL
        || session_id_len == 0u
        || session_id_len > CHAT_CRYPTO_SESSION_ID_MAX) {
        return CHAT_CRYPTO_ERR_INVALID;
    }

    crypto_generichash_state state;
    if (crypto_generichash_init(&state, NULL, 0u, crypto_generichash_BYTES) != 0) {
        return CHAT_CRYPTO_ERR_SODIUM;
    }

    const unsigned char role_byte = (unsigned char)signer_role;
    unsigned char session_len_be[8];
    chat_crypto_write_u64_be(session_len_be, (uint64_t)session_id_len);

    if (crypto_generichash_update(&state,
                                  (const unsigned char *)CHAT_CRYPTO_TRANSCRIPT_DOMAIN,
                                  strlen(CHAT_CRYPTO_TRANSCRIPT_DOMAIN)) != 0
        || crypto_generichash_update(&state, &role_byte, sizeof(role_byte)) != 0
        || crypto_generichash_update(&state,
                                     signer_identity_pk,
                                     crypto_sign_PUBLICKEYBYTES) != 0
        || crypto_generichash_update(&state,
                                     peer_identity_pk,
                                     crypto_sign_PUBLICKEYBYTES) != 0
        || crypto_generichash_update(&state, session_len_be, sizeof(session_len_be)) != 0
        || crypto_generichash_update(&state, session_id, session_id_len) != 0
        || crypto_generichash_update(&state, signer_kx_pk, crypto_kx_PUBLICKEYBYTES) != 0
        || crypto_generichash_final(&state, out_hash, crypto_generichash_BYTES) != 0) {
        sodium_memzero(&state, sizeof(state));
        return CHAT_CRYPTO_ERR_SODIUM;
    }

    sodium_memzero(&state, sizeof(state));
    return CHAT_CRYPTO_OK;
}

const char *chat_crypto_result_name(chat_crypto_result_t result)
{
    switch (result) {
    case CHAT_CRYPTO_OK:
        return "ok";
    case CHAT_CRYPTO_ERR_NULL:
        return "null pointer";
    case CHAT_CRYPTO_ERR_INVALID:
        return "invalid crypto input";
    case CHAT_CRYPTO_ERR_BUFFER:
        return "buffer too small";
    case CHAT_CRYPTO_ERR_SODIUM:
        return "libsodium failure";
    case CHAT_CRYPTO_ERR_VERIFY:
        return "signature verification failed";
    case CHAT_CRYPTO_ERR_DECRYPT:
        return "decryption failed";
    case CHAT_CRYPTO_ERR_TOO_LARGE:
        return "message too large";
    }

    return "unknown crypto error";
}

chat_crypto_result_t chat_crypto_handshake_init(
    chat_crypto_handshake_t *handshake,
    const chat_identity_t *identity,
    const unsigned char remote_identity_pk[crypto_sign_PUBLICKEYBYTES],
    chat_crypto_role_t role,
    const unsigned char *session_id,
    size_t session_id_len,
    unsigned char out_message[CHAT_CRYPTO_KX_MESSAGE_BYTES])
{
    if (handshake == NULL || identity == NULL || remote_identity_pk == NULL || out_message == NULL) {
        return CHAT_CRYPTO_ERR_NULL;
    }

    if (!chat_crypto_role_is_valid(role)
        || session_id == NULL
        || session_id_len == 0u
        || session_id_len > CHAT_CRYPTO_SESSION_ID_MAX) {
        return CHAT_CRYPTO_ERR_INVALID;
    }

    if (sodium_init() < 0) {
        return CHAT_CRYPTO_ERR_SODIUM;
    }

    memset(handshake, 0, sizeof(*handshake));
    handshake->role = role;
    memcpy(handshake->local_identity_pk, identity->public_key, sizeof(handshake->local_identity_pk));
    memcpy(handshake->remote_identity_pk, remote_identity_pk, sizeof(handshake->remote_identity_pk));
    memcpy(handshake->session_id, session_id, session_id_len);
    handshake->session_id_len = session_id_len;

    if (crypto_kx_keypair(handshake->local_kx_pk, handshake->local_kx_sk) != 0) {
        chat_crypto_handshake_wipe(handshake);
        return CHAT_CRYPTO_ERR_SODIUM;
    }

    unsigned char transcript_hash[crypto_generichash_BYTES];
    chat_crypto_result_t result = chat_crypto_transcript_hash(role,
                                                             identity->public_key,
                                                             remote_identity_pk,
                                                             session_id,
                                                             session_id_len,
                                                             handshake->local_kx_pk,
                                                             transcript_hash);
    if (result != CHAT_CRYPTO_OK) {
        chat_crypto_handshake_wipe(handshake);
        return result;
    }

    unsigned char signature[crypto_sign_BYTES];
    if (crypto_sign_detached(signature,
                             NULL,
                             transcript_hash,
                             sizeof(transcript_hash),
                             identity->secret_key) != 0) {
        sodium_memzero(transcript_hash, sizeof(transcript_hash));
        chat_crypto_handshake_wipe(handshake);
        return CHAT_CRYPTO_ERR_SODIUM;
    }
    sodium_memzero(transcript_hash, sizeof(transcript_hash));

    memcpy(out_message, handshake->local_kx_pk, crypto_kx_PUBLICKEYBYTES);
    memcpy(&out_message[crypto_kx_PUBLICKEYBYTES], signature, sizeof(signature));
    sodium_memzero(signature, sizeof(signature));
    handshake->initialized = 1;
    return CHAT_CRYPTO_OK;
}

chat_crypto_result_t chat_crypto_handshake_finish(
    chat_crypto_handshake_t *handshake,
    const unsigned char remote_message[CHAT_CRYPTO_KX_MESSAGE_BYTES],
    chat_crypto_session_keys_t *out_keys)
{
    if (handshake == NULL || remote_message == NULL || out_keys == NULL) {
        return CHAT_CRYPTO_ERR_NULL;
    }

    if (!handshake->initialized || handshake->finished) {
        return CHAT_CRYPTO_ERR_INVALID;
    }

    const unsigned char *remote_kx_pk = remote_message;
    const unsigned char *remote_signature = &remote_message[crypto_kx_PUBLICKEYBYTES];

    unsigned char transcript_hash[crypto_generichash_BYTES];
    chat_crypto_result_t result = chat_crypto_transcript_hash(
        chat_crypto_opposite_role(handshake->role),
        handshake->remote_identity_pk,
        handshake->local_identity_pk,
        handshake->session_id,
        handshake->session_id_len,
        remote_kx_pk,
        transcript_hash);
    if (result != CHAT_CRYPTO_OK) {
        return result;
    }

    if (crypto_sign_verify_detached(remote_signature,
                                    transcript_hash,
                                    sizeof(transcript_hash),
                                    handshake->remote_identity_pk) != 0) {
        sodium_memzero(transcript_hash, sizeof(transcript_hash));
        return CHAT_CRYPTO_ERR_VERIFY;
    }
    sodium_memzero(transcript_hash, sizeof(transcript_hash));

    memset(out_keys, 0, sizeof(*out_keys));
    int derive_result;
    if (handshake->role == CHAT_CRYPTO_ROLE_INITIATOR) {
        derive_result = crypto_kx_client_session_keys(out_keys->rx,
                                                      out_keys->tx,
                                                      handshake->local_kx_pk,
                                                      handshake->local_kx_sk,
                                                      remote_kx_pk);
    } else {
        derive_result = crypto_kx_server_session_keys(out_keys->rx,
                                                      out_keys->tx,
                                                      handshake->local_kx_pk,
                                                      handshake->local_kx_sk,
                                                      remote_kx_pk);
    }

    if (derive_result != 0) {
        chat_crypto_session_keys_wipe(out_keys);
        sodium_memzero(handshake->local_kx_sk, sizeof(handshake->local_kx_sk));
        return CHAT_CRYPTO_ERR_SODIUM;
    }

    handshake->finished = 1;
    sodium_memzero(handshake->local_kx_sk, sizeof(handshake->local_kx_sk));
    return CHAT_CRYPTO_OK;
}

void chat_crypto_handshake_wipe(chat_crypto_handshake_t *handshake)
{
    if (handshake == NULL) {
        return;
    }

    sodium_memzero(handshake, sizeof(*handshake));
}

void chat_crypto_session_keys_wipe(chat_crypto_session_keys_t *keys)
{
    if (keys == NULL) {
        return;
    }

    sodium_memzero(keys, sizeof(*keys));
}

void chat_crypto_secretstream_init(chat_crypto_secretstream_t *stream)
{
    if (stream == NULL) {
        return;
    }

    memset(stream, 0, sizeof(*stream));
}

chat_crypto_result_t chat_crypto_secretstream_init_push(
    chat_crypto_secretstream_t *stream,
    const unsigned char tx_key[crypto_kx_SESSIONKEYBYTES],
    unsigned char out_header[CHAT_CRYPTO_STREAM_HEADER_BYTES])
{
    if (stream == NULL || tx_key == NULL || out_header == NULL) {
        return CHAT_CRYPTO_ERR_NULL;
    }

    if (crypto_secretstream_xchacha20poly1305_init_push(&stream->push,
                                                        out_header,
                                                        tx_key) != 0) {
        return CHAT_CRYPTO_ERR_SODIUM;
    }

    stream->push_initialized = 1;
    return CHAT_CRYPTO_OK;
}

chat_crypto_result_t chat_crypto_secretstream_init_pull(
    chat_crypto_secretstream_t *stream,
    const unsigned char rx_key[crypto_kx_SESSIONKEYBYTES],
    const unsigned char header[CHAT_CRYPTO_STREAM_HEADER_BYTES])
{
    if (stream == NULL || rx_key == NULL || header == NULL) {
        return CHAT_CRYPTO_ERR_NULL;
    }

    if (crypto_secretstream_xchacha20poly1305_init_pull(&stream->pull,
                                                        header,
                                                        rx_key) != 0) {
        return CHAT_CRYPTO_ERR_SODIUM;
    }

    stream->pull_initialized = 1;
    return CHAT_CRYPTO_OK;
}

chat_crypto_result_t chat_crypto_secretstream_encrypt(
    chat_crypto_secretstream_t *stream,
    const unsigned char *plaintext,
    size_t plaintext_len,
    int final,
    unsigned char *ciphertext,
    size_t ciphertext_size,
    size_t *out_ciphertext_len)
{
    if (stream == NULL || ciphertext == NULL || out_ciphertext_len == NULL) {
        return CHAT_CRYPTO_ERR_NULL;
    }

    if (!stream->push_initialized || (plaintext == NULL && plaintext_len != 0u)) {
        return CHAT_CRYPTO_ERR_INVALID;
    }

    if (plaintext_len > CHAT_MAX_MESSAGE_SIZE) {
        return CHAT_CRYPTO_ERR_TOO_LARGE;
    }

    if (ciphertext_size < plaintext_len + CHAT_CRYPTO_STREAM_ABYTES) {
        return CHAT_CRYPTO_ERR_BUFFER;
    }

    unsigned long long ciphertext_len = 0u;
    if (crypto_secretstream_xchacha20poly1305_push(
            &stream->push,
            ciphertext,
            &ciphertext_len,
            plaintext,
            (unsigned long long)plaintext_len,
            NULL,
            0u,
            final ? crypto_secretstream_xchacha20poly1305_TAG_FINAL
                  : crypto_secretstream_xchacha20poly1305_TAG_MESSAGE) != 0) {
        return CHAT_CRYPTO_ERR_SODIUM;
    }

    *out_ciphertext_len = (size_t)ciphertext_len;
    return CHAT_CRYPTO_OK;
}

chat_crypto_result_t chat_crypto_secretstream_decrypt(
    chat_crypto_secretstream_t *stream,
    const unsigned char *ciphertext,
    size_t ciphertext_len,
    unsigned char *plaintext,
    size_t plaintext_size,
    size_t *out_plaintext_len,
    unsigned char *out_tag)
{
    if (stream == NULL
        || ciphertext == NULL
        || plaintext == NULL
        || out_plaintext_len == NULL
        || out_tag == NULL) {
        return CHAT_CRYPTO_ERR_NULL;
    }

    *out_plaintext_len = 0u;
    *out_tag = 0u;

    if (!stream->pull_initialized || ciphertext_len < CHAT_CRYPTO_STREAM_ABYTES) {
        sodium_memzero(plaintext, plaintext_size);
        return CHAT_CRYPTO_ERR_INVALID;
    }

    size_t max_plaintext_len = ciphertext_len - CHAT_CRYPTO_STREAM_ABYTES;
    if (plaintext_size < max_plaintext_len) {
        sodium_memzero(plaintext, plaintext_size);
        return CHAT_CRYPTO_ERR_BUFFER;
    }

    unsigned long long plaintext_len = 0u;
    if (crypto_secretstream_xchacha20poly1305_pull(&stream->pull,
                                                   plaintext,
                                                   &plaintext_len,
                                                   out_tag,
                                                   ciphertext,
                                                   (unsigned long long)ciphertext_len,
                                                   NULL,
                                                   0u) != 0) {
        sodium_memzero(plaintext, plaintext_size);
        *out_plaintext_len = 0u;
        *out_tag = 0u;
        return CHAT_CRYPTO_ERR_DECRYPT;
    }

    *out_plaintext_len = (size_t)plaintext_len;
    return CHAT_CRYPTO_OK;
}

void chat_crypto_secretstream_wipe(chat_crypto_secretstream_t *stream)
{
    if (stream == NULL) {
        return;
    }

    sodium_memzero(stream, sizeof(*stream));
}
