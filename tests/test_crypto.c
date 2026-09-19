#include "common/crypto.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>

static void make_identity(chat_identity_t *identity, const char *username)
{
    memset(identity, 0, sizeof(*identity));
    int written = snprintf(identity->username, sizeof(identity->username), "%s", username);
    assert(written > 0);
    assert((size_t)written < sizeof(identity->username));
    crypto_sign_keypair(identity->public_key, identity->secret_key);
}

static int buffer_is_zero(const unsigned char *buffer, size_t buffer_len)
{
    unsigned char expected[crypto_kx_SECRETKEYBYTES];
    assert(buffer_len <= sizeof(expected));
    memset(expected, 0, sizeof(expected));
    return sodium_memcmp(buffer, expected, buffer_len) == 0;
}

static void perform_handshake(chat_identity_t *alex,
                              chat_identity_t *nathan,
                              chat_crypto_session_keys_t *alex_keys,
                              chat_crypto_session_keys_t *nathan_keys)
{
    const unsigned char session_id[] = "test-session-001";
    unsigned char alex_message[CHAT_CRYPTO_KX_MESSAGE_BYTES];
    unsigned char nathan_message[CHAT_CRYPTO_KX_MESSAGE_BYTES];
    chat_crypto_handshake_t alex_handshake;
    chat_crypto_handshake_t nathan_handshake;

    assert(chat_crypto_handshake_init(&alex_handshake,
                                      alex,
                                      nathan->public_key,
                                      CHAT_CRYPTO_ROLE_INITIATOR,
                                      session_id,
                                      sizeof(session_id) - 1u,
                                      alex_message)
        == CHAT_CRYPTO_OK);
    assert(chat_crypto_handshake_init(&nathan_handshake,
                                      nathan,
                                      alex->public_key,
                                      CHAT_CRYPTO_ROLE_RESPONDER,
                                      session_id,
                                      sizeof(session_id) - 1u,
                                      nathan_message)
        == CHAT_CRYPTO_OK);

    assert(chat_crypto_handshake_finish(&alex_handshake, nathan_message, alex_keys)
        == CHAT_CRYPTO_OK);
    assert(chat_crypto_handshake_finish(&nathan_handshake, alex_message, nathan_keys)
        == CHAT_CRYPTO_OK);

    assert(buffer_is_zero(alex_handshake.local_kx_sk, sizeof(alex_handshake.local_kx_sk)));
    assert(buffer_is_zero(nathan_handshake.local_kx_sk, sizeof(nathan_handshake.local_kx_sk)));

    chat_crypto_handshake_wipe(&alex_handshake);
    chat_crypto_handshake_wipe(&nathan_handshake);
}

static void test_handshake_derives_mirrored_keys(void)
{
    chat_identity_t alex;
    chat_identity_t nathan;
    make_identity(&alex, "alex");
    make_identity(&nathan, "nathan");

    chat_crypto_session_keys_t alex_keys;
    chat_crypto_session_keys_t nathan_keys;
    perform_handshake(&alex, &nathan, &alex_keys, &nathan_keys);

    assert(memcmp(alex_keys.tx, nathan_keys.rx, sizeof(alex_keys.tx)) == 0);
    assert(memcmp(alex_keys.rx, nathan_keys.tx, sizeof(alex_keys.rx)) == 0);
    assert(memcmp(alex_keys.tx, alex_keys.rx, sizeof(alex_keys.tx)) != 0);

    chat_crypto_session_keys_wipe(&alex_keys);
    chat_crypto_session_keys_wipe(&nathan_keys);
    chat_identity_wipe(&alex);
    chat_identity_wipe(&nathan);
}

static void test_handshake_rejects_modified_signature(void)
{
    chat_identity_t alex;
    chat_identity_t nathan;
    make_identity(&alex, "alex");
    make_identity(&nathan, "nathan");

    const unsigned char session_id[] = "test-session-002";
    unsigned char alex_message[CHAT_CRYPTO_KX_MESSAGE_BYTES];
    unsigned char nathan_message[CHAT_CRYPTO_KX_MESSAGE_BYTES];
    chat_crypto_handshake_t alex_handshake;
    chat_crypto_handshake_t nathan_handshake;

    assert(chat_crypto_handshake_init(&alex_handshake,
                                      &alex,
                                      nathan.public_key,
                                      CHAT_CRYPTO_ROLE_INITIATOR,
                                      session_id,
                                      sizeof(session_id) - 1u,
                                      alex_message)
        == CHAT_CRYPTO_OK);
    assert(chat_crypto_handshake_init(&nathan_handshake,
                                      &nathan,
                                      alex.public_key,
                                      CHAT_CRYPTO_ROLE_RESPONDER,
                                      session_id,
                                      sizeof(session_id) - 1u,
                                      nathan_message)
        == CHAT_CRYPTO_OK);

    nathan_message[CHAT_CRYPTO_KX_MESSAGE_BYTES - 1u] ^= 0x80u;
    chat_crypto_session_keys_t keys;
    assert(chat_crypto_handshake_finish(&alex_handshake, nathan_message, &keys)
        == CHAT_CRYPTO_ERR_VERIFY);

    chat_crypto_handshake_wipe(&alex_handshake);
    chat_crypto_handshake_wipe(&nathan_handshake);
    chat_identity_wipe(&alex);
    chat_identity_wipe(&nathan);
}

static void test_handshake_rejects_wrong_remote_identity(void)
{
    chat_identity_t alex;
    chat_identity_t nathan;
    chat_identity_t mallory;
    make_identity(&alex, "alex");
    make_identity(&nathan, "nathan");
    make_identity(&mallory, "mallory");

    const unsigned char session_id[] = "test-session-003";
    unsigned char alex_message[CHAT_CRYPTO_KX_MESSAGE_BYTES];
    unsigned char nathan_message[CHAT_CRYPTO_KX_MESSAGE_BYTES];
    chat_crypto_handshake_t alex_handshake;
    chat_crypto_handshake_t nathan_handshake;

    assert(chat_crypto_handshake_init(&alex_handshake,
                                      &alex,
                                      mallory.public_key,
                                      CHAT_CRYPTO_ROLE_INITIATOR,
                                      session_id,
                                      sizeof(session_id) - 1u,
                                      alex_message)
        == CHAT_CRYPTO_OK);
    assert(chat_crypto_handshake_init(&nathan_handshake,
                                      &nathan,
                                      alex.public_key,
                                      CHAT_CRYPTO_ROLE_RESPONDER,
                                      session_id,
                                      sizeof(session_id) - 1u,
                                      nathan_message)
        == CHAT_CRYPTO_OK);

    chat_crypto_session_keys_t keys;
    assert(chat_crypto_handshake_finish(&alex_handshake, nathan_message, &keys)
        == CHAT_CRYPTO_ERR_VERIFY);

    chat_crypto_handshake_wipe(&alex_handshake);
    chat_crypto_handshake_wipe(&nathan_handshake);
    chat_identity_wipe(&alex);
    chat_identity_wipe(&nathan);
    chat_identity_wipe(&mallory);
}

static void test_secretstream_encrypt_decrypt_and_tamper(void)
{
    chat_identity_t alex;
    chat_identity_t nathan;
    make_identity(&alex, "alex");
    make_identity(&nathan, "nathan");

    chat_crypto_session_keys_t alex_keys;
    chat_crypto_session_keys_t nathan_keys;
    perform_handshake(&alex, &nathan, &alex_keys, &nathan_keys);

    chat_crypto_secretstream_t alex_stream;
    chat_crypto_secretstream_t nathan_stream;
    chat_crypto_secretstream_init(&alex_stream);
    chat_crypto_secretstream_init(&nathan_stream);

    unsigned char stream_header[CHAT_CRYPTO_STREAM_HEADER_BYTES];
    assert(chat_crypto_secretstream_init_push(&alex_stream, alex_keys.tx, stream_header)
        == CHAT_CRYPTO_OK);
    assert(chat_crypto_secretstream_init_pull(&nathan_stream, nathan_keys.rx, stream_header)
        == CHAT_CRYPTO_OK);

    const unsigned char plaintext[] = "salut nathan";
    unsigned char ciphertext[sizeof(plaintext) + CHAT_CRYPTO_STREAM_ABYTES];
    size_t ciphertext_len = 0u;
    assert(chat_crypto_secretstream_encrypt(&alex_stream,
                                            plaintext,
                                            sizeof(plaintext) - 1u,
                                            0,
                                            ciphertext,
                                            sizeof(ciphertext),
                                            &ciphertext_len)
        == CHAT_CRYPTO_OK);

    unsigned char decrypted[sizeof(plaintext)];
    size_t decrypted_len = 0u;
    unsigned char tag = 0u;
    assert(chat_crypto_secretstream_decrypt(&nathan_stream,
                                            ciphertext,
                                            ciphertext_len,
                                            decrypted,
                                            sizeof(decrypted),
                                            &decrypted_len,
                                            &tag)
        == CHAT_CRYPTO_OK);
    assert(tag == crypto_secretstream_xchacha20poly1305_TAG_MESSAGE);
    assert(decrypted_len == sizeof(plaintext) - 1u);
    assert(memcmp(decrypted, plaintext, decrypted_len) == 0);

    chat_crypto_secretstream_t tamper_stream;
    chat_crypto_secretstream_init(&tamper_stream);
    assert(chat_crypto_secretstream_init_pull(&tamper_stream, nathan_keys.rx, stream_header)
        == CHAT_CRYPTO_OK);
    ciphertext[0] ^= 0x01u;
    memset(decrypted, 0xa5, sizeof(decrypted));
    decrypted_len = 123u;
    tag = 77u;
    assert(chat_crypto_secretstream_decrypt(&tamper_stream,
                                            ciphertext,
                                            ciphertext_len,
                                            decrypted,
                                            sizeof(decrypted),
                                            &decrypted_len,
                                            &tag)
        == CHAT_CRYPTO_ERR_DECRYPT);
    assert(decrypted_len == 0u);
    assert(tag == 0u);
    assert(buffer_is_zero(decrypted, sizeof(decrypted)));

    chat_crypto_secretstream_wipe(&alex_stream);
    chat_crypto_secretstream_wipe(&nathan_stream);
    chat_crypto_secretstream_wipe(&tamper_stream);
    chat_crypto_session_keys_wipe(&alex_keys);
    chat_crypto_session_keys_wipe(&nathan_keys);
    chat_identity_wipe(&alex);
    chat_identity_wipe(&nathan);
}

static void test_secretstream_rejects_wrong_key(void)
{
    chat_identity_t alex;
    chat_identity_t nathan;
    make_identity(&alex, "alex");
    make_identity(&nathan, "nathan");

    chat_crypto_session_keys_t alex_keys;
    chat_crypto_session_keys_t nathan_keys;
    perform_handshake(&alex, &nathan, &alex_keys, &nathan_keys);

    chat_crypto_secretstream_t alex_stream;
    chat_crypto_secretstream_t wrong_stream;
    chat_crypto_secretstream_init(&alex_stream);
    chat_crypto_secretstream_init(&wrong_stream);

    unsigned char stream_header[CHAT_CRYPTO_STREAM_HEADER_BYTES];
    assert(chat_crypto_secretstream_init_push(&alex_stream, alex_keys.tx, stream_header)
        == CHAT_CRYPTO_OK);
    assert(chat_crypto_secretstream_init_pull(&wrong_stream, nathan_keys.tx, stream_header)
        == CHAT_CRYPTO_OK);

    const unsigned char plaintext[] = "wrong key test";
    unsigned char ciphertext[sizeof(plaintext) + CHAT_CRYPTO_STREAM_ABYTES];
    size_t ciphertext_len = 0u;
    assert(chat_crypto_secretstream_encrypt(&alex_stream,
                                            plaintext,
                                            sizeof(plaintext) - 1u,
                                            1,
                                            ciphertext,
                                            sizeof(ciphertext),
                                            &ciphertext_len)
        == CHAT_CRYPTO_OK);

    unsigned char decrypted[sizeof(plaintext)];
    memset(decrypted, 0xa5, sizeof(decrypted));
    size_t decrypted_len = 123u;
    unsigned char tag = 77u;
    assert(chat_crypto_secretstream_decrypt(&wrong_stream,
                                            ciphertext,
                                            ciphertext_len,
                                            decrypted,
                                            sizeof(decrypted),
                                            &decrypted_len,
                                            &tag)
        == CHAT_CRYPTO_ERR_DECRYPT);
    assert(decrypted_len == 0u);
    assert(tag == 0u);
    assert(buffer_is_zero(decrypted, sizeof(decrypted)));

    chat_crypto_secretstream_wipe(&alex_stream);
    chat_crypto_secretstream_wipe(&wrong_stream);
    chat_crypto_session_keys_wipe(&alex_keys);
    chat_crypto_session_keys_wipe(&nathan_keys);
    chat_identity_wipe(&alex);
    chat_identity_wipe(&nathan);
}

int main(void)
{
    assert(sodium_init() >= 0);
    test_handshake_derives_mirrored_keys();
    test_handshake_rejects_modified_signature();
    test_handshake_rejects_wrong_remote_identity();
    test_secretstream_encrypt_decrypt_and_tamper();
    test_secretstream_rejects_wrong_key();
    return 0;
}
