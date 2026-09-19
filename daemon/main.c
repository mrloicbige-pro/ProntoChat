#define _POSIX_C_SOURCE 200809L

#include "daemon/ice.h"

#include "common/contacts.h"
#include "common/crypto.h"
#include "common/identity.h"
#include "common/ipc.h"
#include "common/log.h"
#include "common/protocole.h"

#include <errno.h>
#include <fcntl.h>
#include <libwebsockets.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define CHATD_CONTROL_PROTOCOL "chat-control-v1"
#define CHATD_MAX_JSON_SIZE 4096u
#define CHATD_RECONNECT_SECONDS 1
#define CHATD_HEX_PUBLIC_KEY_LEN (crypto_sign_PUBLICKEYBYTES * 2u + 1u)
#define CHATD_HEX_SIGNATURE_LEN (crypto_sign_BYTES * 2u + 1u)
#define CHATD_CHALLENGE_BYTES 32u
#define CHATD_HEX_CHALLENGE_LEN (CHATD_CHALLENGE_BYTES * 2u + 1u)
#define CHATD_SESSION_ID_BYTES 16u
#define CHATD_SESSION_ID_HEX_LEN (CHATD_SESSION_ID_BYTES * 2u + 1u)
#define CHATD_ICE_TIMEOUT_SECONDS 30
#define CHATD_CRYPTO_TIMEOUT_SECONDS 30
#define CHATD_ICE_RETRY_MAX 3
#define CHATD_ICE_SDP_MAX 2048u
#define CHATD_ICE_PACKET_MAX CHAT_ICE_RECV_MAX
#define CHATD_CHAT_TEXT_MAX (CHAT_IPC_MAX_COMMAND - sizeof("SEND_MESSAGE \n"))

typedef enum {
    CHATD_PHASE_REGISTER,
    CHATD_PHASE_HELLO,
    CHATD_PHASE_AUTH_RESPONSE,
    CHATD_PHASE_ONLINE,
    CHATD_PHASE_FAILED
} chatd_phase_t;

typedef enum {
    CHATD_SESSION_IDLE,
    CHATD_SESSION_LOOKUP,
    CHATD_SESSION_REQUESTING,
    CHATD_SESSION_ICE_NEGOTIATING,
    CHATD_SESSION_ICE_CONNECTED,
    CHATD_SESSION_CRYPTO_HANDSHAKE,
    CHATD_SESSION_SECURE,
    CHATD_SESSION_CLOSING,
    CHATD_SESSION_CLOSED,
    CHATD_SESSION_FAILED
} chatd_session_state_t;

typedef struct {
    chat_identity_t identity;
    struct lws_context *context;
    struct lws *control_wsi;
    chatd_phase_t phase;
    chatd_session_state_t session_state;
    unsigned char challenge[CHATD_CHALLENGE_BYTES];
    int has_challenge;
    int connected;
    int should_reconnect;
    time_t next_reconnect_at;
    int ipc_fd;
    int pending_ipc_client_fd;
    time_t pending_ipc_deadline_at;
    pthread_t wakeup_thread;
    int wakeup_thread_started;
    pthread_mutex_t lock;
    int lookup_client_fd;
    char lookup_peer[CHAT_USERNAME_MAX_LEN + 1u];
    int chat_retry_count;
    char ice_peer[CHAT_USERNAME_MAX_LEN + 1u];
    char ice_session_id[CHATD_SESSION_ID_HEX_LEN];
    chat_ice_config_t ice_config;
    chat_ice_session_t ice;
    int ice_active;
    int ice_controlling;
    int ice_local_sdp_sent;
    int ice_cli_notified;
    int ice_selected_pair_is_relayed;
    time_t ice_deadline_at;
    char pending_remote_ice_sdp[CHATD_ICE_SDP_MAX + 1u];
    int has_pending_remote_ice_sdp;
    unsigned char remote_identity_pk[crypto_sign_PUBLICKEYBYTES];
    int has_remote_identity_pk;
    chat_crypto_role_t crypto_role;
    chat_crypto_handshake_t crypto_handshake;
    chat_crypto_session_keys_t crypto_keys;
    chat_crypto_secretstream_t crypto_stream;
    unsigned char crypto_local_handshake_message[CHAT_CRYPTO_KX_MESSAGE_BYTES];
    unsigned char crypto_local_stream_header[CHAT_CRYPTO_STREAM_HEADER_BYTES];
    time_t crypto_deadline_at;
    int crypto_handshake_sent;
    time_t crypto_next_handshake_at;
    int crypto_keys_ready;
    int crypto_stream_header_sent;
    time_t crypto_next_stream_header_at;
    int crypto_stream_header_received;
    int encrypted_session_ready;
    char ipc_socket_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
    unsigned char pending[LWS_PRE + CHATD_MAX_JSON_SIZE];
    size_t pending_len;
} chatd_state_t;

static volatile sig_atomic_t g_interrupted = 0;

static int write_ipc_line(int fd, const char *line);
static void write_lookup_response(chatd_state_t *state, const char *prefix, const char *username);
static void close_lookup_client(chatd_state_t *state);

static int parse_config_uint(const char *value, unsigned int *out)
{
    if (value == NULL || out == NULL || value[0] == '\0') {
        return -1;
    }

    char *end = NULL;
    unsigned long parsed = strtoul(value, &end, 10);
    if (end == value || *end != '\0' || parsed == 0ul || parsed > 65535ul) {
        return -1;
    }

    *out = (unsigned int)parsed;
    return 0;
}

static int load_optional_config_value(const char *key, char *out, size_t out_size)
{
    chat_identity_result_t result = chat_identity_load_config_value(key, out, out_size);
    if (result == CHAT_IDENTITY_ERR_NOT_FOUND) {
        if (out != NULL && out_size > 0u) {
            out[0] = '\0';
        }
        return 0;
    }

    return result == CHAT_IDENTITY_OK ? 1 : -1;
}

static int load_ice_config(chat_ice_config_t *config)
{
    if (config == NULL) {
        return -1;
    }

    chat_ice_config_init(config);

    int has_local_address = load_optional_config_value("ice_local_address",
                                                       config->local_address,
                                                       sizeof(config->local_address));
    if (has_local_address < 0) {
        return -1;
    }
    if (has_local_address == 1) {
        if (config->local_address[0] == '\0') {
            return -1;
        }
        config->has_local_address = 1;
    }

    char port_value[16];
    int has_stun_host = load_optional_config_value("stun_server",
                                                   config->stun_host,
                                                   sizeof(config->stun_host));
    int has_stun_port = load_optional_config_value("stun_port",
                                                   port_value,
                                                   sizeof(port_value));
    if (has_stun_host < 0 || has_stun_port < 0) {
        return -1;
    }
    if (has_stun_host == 1 || has_stun_port == 1) {
        if (has_stun_host != 1
            || has_stun_port != 1
            || parse_config_uint(port_value, &config->stun_port) != 0) {
            return -1;
        }
        config->has_stun = 1;
    }

    int has_turn_host = load_optional_config_value("turn_server",
                                                   config->turn_host,
                                                   sizeof(config->turn_host));
    int has_turn_port = load_optional_config_value("turn_port",
                                                   port_value,
                                                   sizeof(port_value));
    int has_turn_username = load_optional_config_value("turn_username",
                                                       config->turn_username,
                                                       sizeof(config->turn_username));
    int has_turn_password = load_optional_config_value("turn_password",
                                                       config->turn_password,
                                                       sizeof(config->turn_password));
    if (has_turn_host < 0 || has_turn_port < 0 || has_turn_username < 0 || has_turn_password < 0) {
        return -1;
    }
    if (has_turn_host == 1 || has_turn_port == 1 || has_turn_username == 1 || has_turn_password == 1) {
        if (has_turn_host != 1
            || has_turn_port != 1
            || has_turn_username != 1
            || has_turn_password != 1
            || config->turn_username[0] == '\0'
            || config->turn_password[0] == '\0'
            || parse_config_uint(port_value, &config->turn_port) != 0) {
            sodium_memzero(config->turn_password, sizeof(config->turn_password));
            return -1;
        }
        config->has_turn = 1;
    }

    char force_relay_value[8];
    int has_force_relay = load_optional_config_value("ice_force_relay",
                                                     force_relay_value,
                                                     sizeof(force_relay_value));
    if (has_force_relay < 0) {
        return -1;
    }
    if (has_force_relay == 1) {
        if (strcmp(force_relay_value, "true") == 0) {
            if (!config->has_turn) {
                return -1;
            }
            config->force_relay = 1;
        } else if (strcmp(force_relay_value, "false") != 0) {
            return -1;
        }
    }

    return 0;
}

static void wipe_ice_config(chat_ice_config_t *config)
{
    if (config == NULL) {
        return;
    }

    sodium_memzero(config, sizeof(*config));
}

static const char *chatd_session_state_name(chatd_session_state_t state)
{
    switch (state) {
    case CHATD_SESSION_IDLE:
        return "IDLE";
    case CHATD_SESSION_LOOKUP:
        return "LOOKUP";
    case CHATD_SESSION_REQUESTING:
        return "REQUESTING";
    case CHATD_SESSION_ICE_NEGOTIATING:
        return "ICE_NEGOTIATING";
    case CHATD_SESSION_ICE_CONNECTED:
        return "ICE_CONNECTED";
    case CHATD_SESSION_CRYPTO_HANDSHAKE:
        return "CRYPTO_HANDSHAKE";
    case CHATD_SESSION_SECURE:
        return "SECURE";
    case CHATD_SESSION_CLOSING:
        return "CLOSING";
    case CHATD_SESSION_CLOSED:
        return "CLOSED";
    case CHATD_SESSION_FAILED:
        return "FAILED";
    }

    return "UNKNOWN";
}

static void chatd_set_session_state(chatd_state_t *state, chatd_session_state_t next)
{
    if (state == NULL || state->session_state == next) {
        return;
    }

    chat_log(CHAT_LOG_DEBUG,
             "session state %s -> %s",
             chatd_session_state_name(state->session_state),
             chatd_session_state_name(next));
    state->session_state = next;
}

static void handle_signal(int signal_number)
{
    (void)signal_number;
    g_interrupted = 1;
}

static int json_get_string(const char *json, const char *key, char *out, size_t out_size)
{
    if (json == NULL || key == NULL || out == NULL || out_size == 0u) {
        return 0;
    }

    char pattern[64];
    int pattern_len = snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    if (pattern_len < 0 || (size_t)pattern_len >= sizeof(pattern)) {
        return 0;
    }

    const char *cursor = strstr(json, pattern);
    if (cursor == NULL) {
        return 0;
    }

    cursor += pattern_len;
    while (*cursor == ' ' || *cursor == '\t' || *cursor == '\r' || *cursor == '\n') {
        ++cursor;
    }
    if (*cursor != ':') {
        return 0;
    }
    ++cursor;
    while (*cursor == ' ' || *cursor == '\t' || *cursor == '\r' || *cursor == '\n') {
        ++cursor;
    }
    if (*cursor != '"') {
        return 0;
    }
    ++cursor;

    size_t offset = 0u;
    while (*cursor != '\0' && *cursor != '"') {
        unsigned char ch = (unsigned char)*cursor;
        if (ch < 0x20u || ch == '\\' || offset + 1u >= out_size) {
            return 0;
        }
        out[offset++] = *cursor++;
    }

    if (*cursor != '"') {
        return 0;
    }

    out[offset] = '\0';
    return 1;
}

static int hex_to_bin(const char *hex, unsigned char *out, size_t out_size)
{
    size_t bin_len = 0u;
    if (sodium_hex2bin(out, out_size, hex, strlen(hex), NULL, &bin_len, NULL) != 0) {
        return 0;
    }

    return bin_len == out_size;
}

static int base64_encode_sdp(const char *sdp, char *out, size_t out_size)
{
    if (sdp == NULL || out == NULL || out_size == 0u) {
        return 0;
    }

    size_t sdp_len = strlen(sdp);
    size_t required = sodium_base64_encoded_len(sdp_len, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    if (sdp_len > CHATD_ICE_SDP_MAX || required > out_size) {
        return 0;
    }

    return sodium_bin2base64(out,
                             out_size,
                             (const unsigned char *)sdp,
                             sdp_len,
                             sodium_base64_VARIANT_URLSAFE_NO_PADDING) != NULL;
}

static int base64_decode_sdp(const char *encoded, char *out, size_t out_size)
{
    if (encoded == NULL || out == NULL || out_size == 0u) {
        return 0;
    }

    size_t decoded_len = 0u;
    if (sodium_base642bin((unsigned char *)out,
                          out_size - 1u,
                          encoded,
                          strlen(encoded),
                          NULL,
                          &decoded_len,
                          NULL,
                          sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0) {
        return 0;
    }

    out[decoded_len] = '\0';
    return decoded_len > 0u;
}

static int queue_json(struct lws *wsi, chatd_state_t *state, const char *json)
{
    size_t len = strlen(json);
    if (len >= CHATD_MAX_JSON_SIZE) {
        state->phase = CHATD_PHASE_FAILED;
        return -1;
    }

    pthread_mutex_lock(&state->lock);
    if (state->pending_len != 0u) {
        pthread_mutex_unlock(&state->lock);
        return -1;
    }
    memcpy(&state->pending[LWS_PRE], json, len);
    state->pending_len = len;
    pthread_mutex_unlock(&state->lock);

    (void)lws_callback_on_writable_all_protocol(lws_get_context(wsi), lws_get_protocol(wsi));
    lws_cancel_service_pt(wsi);
    return 0;
}

static int has_pending_control_message(chatd_state_t *state)
{
    pthread_mutex_lock(&state->lock);
    int has_pending = state->pending_len != 0u;
    pthread_mutex_unlock(&state->lock);
    return has_pending;
}

static int queue_register(struct lws *wsi, chatd_state_t *state)
{
    char public_key_hex[CHATD_HEX_PUBLIC_KEY_LEN];
    (void)sodium_bin2hex(public_key_hex,
                         sizeof(public_key_hex),
                         state->identity.public_key,
                         sizeof(state->identity.public_key));

    char json[512];
    int written = snprintf(json,
                           sizeof(json),
                           "{\"type\":\"register\",\"username\":\"%s\",\"public_key\":\"%s\"}",
                           state->identity.username,
                           public_key_hex);
    if (written < 0 || (size_t)written >= sizeof(json)) {
        return -1;
    }

    return queue_json(wsi, state, json);
}

static int queue_hello(struct lws *wsi, chatd_state_t *state)
{
    char json[128];
    int written = snprintf(json,
                           sizeof(json),
                           "{\"type\":\"hello\",\"username\":\"%s\"}",
                           state->identity.username);
    if (written < 0 || (size_t)written >= sizeof(json)) {
        return -1;
    }

    return queue_json(wsi, state, json);
}

static int queue_auth_response(struct lws *wsi, chatd_state_t *state)
{
    unsigned char signature[crypto_sign_BYTES];
    if (crypto_sign_detached(signature,
                             NULL,
                             state->challenge,
                             sizeof(state->challenge),
                             state->identity.secret_key) != 0) {
        return -1;
    }

    char signature_hex[CHATD_HEX_SIGNATURE_LEN];
    (void)sodium_bin2hex(signature_hex, sizeof(signature_hex), signature, sizeof(signature));
    sodium_memzero(signature, sizeof(signature));

    char json[256];
    int written = snprintf(json,
                           sizeof(json),
                           "{\"type\":\"auth_response\",\"signature\":\"%s\"}",
                           signature_hex);
    if (written < 0 || (size_t)written >= sizeof(json)) {
        return -1;
    }

    return queue_json(wsi, state, json);
}

static int json_bool_is_true(const char *json, const char *key)
{
    char pattern[64];
    int pattern_len = snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    if (pattern_len < 0 || (size_t)pattern_len >= sizeof(pattern)) {
        return 0;
    }

    const char *cursor = strstr(json, pattern);
    if (cursor == NULL) {
        return 0;
    }

    cursor += pattern_len;
    while (*cursor == ' ' || *cursor == '\t' || *cursor == '\r' || *cursor == '\n') {
        ++cursor;
    }
    if (*cursor != ':') {
        return 0;
    }
    ++cursor;
    while (*cursor == ' ' || *cursor == '\t' || *cursor == '\r' || *cursor == '\n') {
        ++cursor;
    }

    return strncmp(cursor, "true", 4u) == 0;
}

static int queue_chat_accept(struct lws *wsi,
                             chatd_state_t *state,
                             const char *peer,
                             const char *session_id)
{
    char public_key_hex[CHATD_HEX_PUBLIC_KEY_LEN];
    (void)sodium_bin2hex(public_key_hex,
                         sizeof(public_key_hex),
                         state->identity.public_key,
                         sizeof(state->identity.public_key));

    char json[512];
    int written = snprintf(json,
                           sizeof(json),
                           "{\"type\":\"chat_accept\",\"from\":\"%s\",\"to\":\"%s\","
                           "\"session_id\":\"%s\",\"public_key\":\"%s\"}",
                           state->identity.username,
                           peer,
                           session_id,
                           public_key_hex);
    if (written < 0 || (size_t)written >= sizeof(json)) {
        return -1;
    }

    return queue_json(wsi, state, json);
}

static int queue_chat_request(struct lws *wsi,
                              chatd_state_t *state,
                              const char *peer,
                              char session_id[CHATD_SESSION_ID_HEX_LEN])
{
    unsigned char session_id_bytes[CHATD_SESSION_ID_BYTES];
    randombytes_buf(session_id_bytes, sizeof(session_id_bytes));
    (void)sodium_bin2hex(session_id,
                         CHATD_SESSION_ID_HEX_LEN,
                         session_id_bytes,
                         sizeof(session_id_bytes));
    sodium_memzero(session_id_bytes, sizeof(session_id_bytes));

    char public_key_hex[CHATD_HEX_PUBLIC_KEY_LEN];
    (void)sodium_bin2hex(public_key_hex,
                         sizeof(public_key_hex),
                         state->identity.public_key,
                         sizeof(state->identity.public_key));

    char json[512];
    int written = snprintf(json,
                           sizeof(json),
                           "{\"type\":\"chat_request\",\"from\":\"%s\",\"to\":\"%s\","
                           "\"session_id\":\"%s\",\"public_key\":\"%s\"}",
                           state->identity.username,
                           peer,
                           session_id,
                           public_key_hex);
    if (written < 0 || (size_t)written >= sizeof(json)) {
        return -1;
    }

    return queue_json(wsi, state, json);
}

static int queue_chat_cancel(struct lws *wsi,
                             chatd_state_t *state,
                             const char *peer,
                             const char *session_id)
{
    char json[384];
    int written = snprintf(json,
                           sizeof(json),
                           "{\"type\":\"chat_cancel\",\"from\":\"%s\",\"to\":\"%s\","
                           "\"session_id\":\"%s\"}",
                           state->identity.username,
                           peer,
                           session_id);
    if (written < 0 || (size_t)written >= sizeof(json)) {
        return -1;
    }

    return queue_json(wsi, state, json);
}

static void reset_ice_session(chatd_state_t *state)
{
    chat_ice_session_close(&state->ice);
    chat_crypto_handshake_wipe(&state->crypto_handshake);
    chat_crypto_session_keys_wipe(&state->crypto_keys);
    chat_crypto_secretstream_wipe(&state->crypto_stream);
    state->ice_active = 0;
    state->ice_controlling = 0;
    state->ice_local_sdp_sent = 0;
    state->ice_cli_notified = 0;
    state->ice_selected_pair_is_relayed = 0;
    state->ice_peer[0] = '\0';
    state->ice_session_id[0] = '\0';
    state->ice_deadline_at = 0;
    state->pending_remote_ice_sdp[0] = '\0';
    state->has_pending_remote_ice_sdp = 0;
    sodium_memzero(state->remote_identity_pk, sizeof(state->remote_identity_pk));
    sodium_memzero(state->crypto_local_handshake_message,
                   sizeof(state->crypto_local_handshake_message));
    sodium_memzero(state->crypto_local_stream_header,
                   sizeof(state->crypto_local_stream_header));
    state->has_remote_identity_pk = 0;
    state->crypto_role = 0;
    state->crypto_deadline_at = 0;
    state->crypto_handshake_sent = 0;
    state->crypto_next_handshake_at = 0;
    state->crypto_keys_ready = 0;
    state->crypto_stream_header_sent = 0;
    state->crypto_next_stream_header_at = 0;
    state->crypto_stream_header_received = 0;
    state->encrypted_session_ready = 0;
}

static int retry_outgoing_chat_session(chatd_state_t *state)
{
    if (state->lookup_client_fd < 0
        || state->lookup_peer[0] == '\0'
        || state->control_wsi == NULL
        || state->encrypted_session_ready
        || state->chat_retry_count >= CHATD_ICE_RETRY_MAX) {
        return -1;
    }

    char peer[CHAT_USERNAME_MAX_LEN + 1u];
    int copied = snprintf(peer, sizeof(peer), "%s", state->lookup_peer);
    if (copied < 0 || (size_t)copied >= sizeof(peer)) {
        return -1;
    }

    state->chat_retry_count++;
    chat_log(CHAT_LOG_WARN,
             "retrying chat session with %s after ICE/crypto setup failure (%d/%d)",
             peer,
             state->chat_retry_count,
             CHATD_ICE_RETRY_MAX);
    reset_ice_session(state);
    chatd_set_session_state(state, CHATD_SESSION_REQUESTING);

    if (queue_chat_request(state->control_wsi,
                           state,
                           peer,
                           state->ice_session_id) != 0) {
        write_lookup_response(state, "ERROR", "chat_retry_failed");
        return 0;
    }

    return 0;
}

static void fail_chat_session(chatd_state_t *state)
{
    if (retry_outgoing_chat_session(state) == 0) {
        return;
    }

    chatd_set_session_state(state, CHATD_SESSION_FAILED);
    if (state->lookup_client_fd >= 0) {
        if (state->encrypted_session_ready) {
            (void)write_ipc_line(state->lookup_client_fd, "ERROR session_failed\n");
            close_lookup_client(state);
        } else if (state->ice_peer[0] != '\0') {
            write_lookup_response(state, "ICE_FAILED", state->ice_peer);
        } else if (state->lookup_peer[0] != '\0') {
            write_lookup_response(state, "ICE_FAILED", state->lookup_peer);
        } else {
            (void)write_ipc_line(state->lookup_client_fd, "ERROR session_failed\n");
            close_lookup_client(state);
        }
    }
    reset_ice_session(state);
}

static int begin_ice_session(struct lws *wsi,
                             chatd_state_t *state,
                             const char *peer,
                             const char *session_id,
                             int controlling,
                             const unsigned char remote_identity_pk[crypto_sign_PUBLICKEYBYTES])
{
    (void)wsi;

    if (remote_identity_pk == NULL) {
        return -1;
    }

    reset_ice_session(state);
    chatd_set_session_state(state, CHATD_SESSION_ICE_NEGOTIATING);

    int copied = snprintf(state->ice_peer, sizeof(state->ice_peer), "%s", peer);
    if (copied < 0 || (size_t)copied >= sizeof(state->ice_peer)) {
        fail_chat_session(state);
        return -1;
    }

    copied = snprintf(state->ice_session_id, sizeof(state->ice_session_id), "%s", session_id);
    if (copied < 0 || (size_t)copied >= sizeof(state->ice_session_id)) {
        fail_chat_session(state);
        return -1;
    }

    memcpy(state->remote_identity_pk,
           remote_identity_pk,
           sizeof(state->remote_identity_pk));
    state->has_remote_identity_pk = 1;
    state->crypto_role = controlling
        ? CHAT_CRYPTO_ROLE_INITIATOR
        : CHAT_CRYPTO_ROLE_RESPONDER;
    state->ice_controlling = controlling;
    chat_crypto_secretstream_init(&state->crypto_stream);

    chat_ice_result_t result = chat_ice_session_start(&state->ice,
                                                      controlling,
                                                      &state->ice_config);
    if (result != CHAT_ICE_OK) {
        chat_log(CHAT_LOG_ERROR, "failed to start ICE: %s", chat_ice_result_name(result));
        fail_chat_session(state);
        return -1;
    }

    state->ice_active = 1;
    state->ice_deadline_at = time(NULL) + CHATD_ICE_TIMEOUT_SECONDS;
    chat_log(CHAT_LOG_INFO,
             "started ICE session with %s as %s",
             peer,
             controlling ? "controlling" : "controlled");
    return 0;
}

static int apply_remote_ice_sdp(chatd_state_t *state, const char *from, const char *sdp)
{
    chat_ice_result_t result = chat_ice_session_set_remote_sdp(&state->ice, sdp);
    if (result != CHAT_ICE_OK) {
        chat_log(CHAT_LOG_ERROR, "failed to apply remote ICE SDP: %s",
                 chat_ice_result_name(result));
        state->ice.failed = 1;
        return -1;
    }

    chat_log(CHAT_LOG_INFO, "applied remote ICE SDP from %s", from);
    return 0;
}

static int queue_local_ice_sdp(struct lws *wsi, chatd_state_t *state)
{
    char *sdp = NULL;
    chat_ice_result_t result = chat_ice_session_generate_local_sdp(&state->ice, &sdp);
    if (result != CHAT_ICE_OK) {
        chat_log(CHAT_LOG_ERROR, "failed to generate local ICE SDP: %s",
                 chat_ice_result_name(result));
        return -1;
    }

    char encoded[sodium_base64_ENCODED_LEN(CHATD_ICE_SDP_MAX,
                                           sodium_base64_VARIANT_URLSAFE_NO_PADDING)];
    if (!base64_encode_sdp(sdp, encoded, sizeof(encoded))) {
        chat_ice_free_string(sdp);
        chat_log(CHAT_LOG_ERROR, "local ICE SDP is too large");
        return -1;
    }
    chat_ice_free_string(sdp);

    char json[CHATD_MAX_JSON_SIZE];
    int written = snprintf(json,
                           sizeof(json),
                           "{\"type\":\"ice_credentials\",\"from\":\"%s\",\"to\":\"%s\","
                           "\"session_id\":\"%s\",\"sdp\":\"%s\"}",
                           state->identity.username,
                           state->ice_peer,
                           state->ice_session_id,
                           encoded);
    if (written < 0 || (size_t)written >= sizeof(json)) {
        chat_log(CHAT_LOG_ERROR, "local ICE signalling message is too large");
        return -1;
    }

    if (queue_json(wsi, state, json) != 0) {
        return -1;
    }

    state->ice_local_sdp_sent = 1;
    chat_log(CHAT_LOG_INFO, "sent local ICE SDP to %s", state->ice_peer);
    return 0;
}

static int handle_ice_credentials(chatd_state_t *state, const char *json)
{
    char from[CHAT_USERNAME_MAX_LEN + 1u];
    char to[CHAT_USERNAME_MAX_LEN + 1u];
    char session_id[CHATD_SESSION_ID_HEX_LEN];
    char encoded[sodium_base64_ENCODED_LEN(CHATD_ICE_SDP_MAX,
                                           sodium_base64_VARIANT_URLSAFE_NO_PADDING)];
    char sdp[CHATD_ICE_SDP_MAX + 1u];

    if (!state->ice_active
        || !json_get_string(json, "from", from, sizeof(from))
        || !json_get_string(json, "to", to, sizeof(to))
        || !json_get_string(json, "session_id", session_id, sizeof(session_id))
        || !json_get_string(json, "sdp", encoded, sizeof(encoded))
        || strcmp(from, state->ice_peer) != 0
        || strcmp(to, state->identity.username) != 0
        || strcmp(session_id, state->ice_session_id) != 0
        || !base64_decode_sdp(encoded, sdp, sizeof(sdp))) {
        chat_log(CHAT_LOG_WARN, "invalid ICE credentials received");
        return 0;
    }

    if (!state->ice.gathering_done) {
        int copied = snprintf(state->pending_remote_ice_sdp,
                              sizeof(state->pending_remote_ice_sdp),
                              "%s",
                              sdp);
        if (copied < 0 || (size_t)copied >= sizeof(state->pending_remote_ice_sdp)) {
            state->ice.failed = 1;
            return -1;
        }
        state->has_pending_remote_ice_sdp = 1;
        chat_log(CHAT_LOG_INFO, "queued remote ICE SDP from %s until local gathering completes", from);
        return 0;
    }

    return apply_remote_ice_sdp(state, from, sdp);
}

static int send_ice_packet(chatd_state_t *state,
                           chat_packet_type_t type,
                           const unsigned char *payload,
                           size_t payload_len)
{
    if (state == NULL || (payload == NULL && payload_len != 0u)) {
        return -1;
    }

    if (payload_len > CHAT_MAX_MESSAGE_SIZE
        || CHAT_PACKET_HEADER_SIZE + payload_len > CHATD_ICE_PACKET_MAX) {
        return -1;
    }

    unsigned char packet[CHATD_ICE_PACKET_MAX];
    chat_protocol_result_t protocol_result =
        chat_packet_encode_header(type, (uint32_t)payload_len, packet);
    if (protocol_result != CHAT_PROTOCOL_OK) {
        return -1;
    }

    if (payload_len > 0u) {
        memcpy(&packet[CHAT_PACKET_HEADER_SIZE], payload, payload_len);
    }

    chat_ice_result_t ice_result = chat_ice_send(&state->ice,
                                                 packet,
                                                 CHAT_PACKET_HEADER_SIZE + payload_len);
    sodium_memzero(packet, CHAT_PACKET_HEADER_SIZE + payload_len);
    if (ice_result != CHAT_ICE_OK) {
        chat_log(CHAT_LOG_ERROR, "failed to send ICE packet: %s",
                 chat_ice_result_name(ice_result));
        return -1;
    }

    return 0;
}

static int write_ipc_line(int fd, const char *line)
{
    if (fd < 0 || line == NULL) {
        return -1;
    }

    size_t line_len = strlen(line);
    size_t offset = 0u;
    while (offset < line_len) {
        ssize_t written = write(fd, &line[offset], line_len - offset);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct timespec sleep_time = {.tv_sec = 0, .tv_nsec = 1000 * 1000};
            (void)nanosleep(&sleep_time, NULL);
            continue;
        }
        if (written <= 0) {
            chat_log(CHAT_LOG_WARN, "IPC write failed: %s", strerror(errno));
            return -1;
        }
        offset += (size_t)written;
    }

    return 0;
}

static int chat_text_is_valid(const char *text, size_t text_len)
{
    if (text == NULL || text_len == 0u || text_len > CHATD_CHAT_TEXT_MAX) {
        return 0;
    }

    for (size_t i = 0u; i < text_len; ++i) {
        unsigned char ch = (unsigned char)text[i];
        if (ch == '\0' || ch == '\r' || ch == '\n') {
            return 0;
        }
    }

    return 1;
}

static int send_encrypted_chat_payload(chatd_state_t *state,
                                       chat_packet_type_t type,
                                       const unsigned char *plaintext,
                                       size_t plaintext_len,
                                       int final)
{
    if (state == NULL
        || !state->encrypted_session_ready
        || (state->session_state != CHATD_SESSION_SECURE
            && state->session_state != CHATD_SESSION_CLOSING)
        || (plaintext == NULL && plaintext_len != 0u)
        || plaintext_len + CHAT_CRYPTO_STREAM_ABYTES > CHAT_MAX_MESSAGE_SIZE) {
        return -1;
    }

    unsigned char ciphertext[CHAT_MAX_MESSAGE_SIZE];
    size_t ciphertext_len = 0u;
    chat_crypto_result_t crypto_result =
        chat_crypto_secretstream_encrypt(&state->crypto_stream,
                                          plaintext,
                                          plaintext_len,
                                          final,
                                          ciphertext,
                                          sizeof(ciphertext),
                                          &ciphertext_len);
    if (crypto_result != CHAT_CRYPTO_OK) {
        chat_log(CHAT_LOG_ERROR, "failed to encrypt chat payload: %s",
                 chat_crypto_result_name(crypto_result));
        return -1;
    }

    int sent = send_ice_packet(state, type, ciphertext, ciphertext_len);
    sodium_memzero(ciphertext, ciphertext_len);
    return sent;
}

static int send_encrypted_chat_message(chatd_state_t *state, const char *text, size_t text_len)
{
    if (!chat_text_is_valid(text, text_len)) {
        return -1;
    }

    return send_encrypted_chat_payload(state,
                                       CHAT_PKT_MESSAGE,
                                       (const unsigned char *)text,
                                       text_len,
                                       0);
}

static int send_encrypted_chat_close(chatd_state_t *state)
{
    chatd_set_session_state(state, CHATD_SESSION_CLOSING);
    return send_encrypted_chat_payload(state, CHAT_PKT_CLOSE, NULL, 0u, 1);
}

static int write_chat_message_to_cli(chatd_state_t *state,
                                     const unsigned char *plaintext,
                                     size_t plaintext_len)
{
    if (state->lookup_client_fd < 0) {
        return 0;
    }

    size_t prefix_len = strlen("MESSAGE ") + strlen(state->ice_peer) + 1u;
    if (plaintext_len + prefix_len + 2u > CHAT_IPC_MAX_RESPONSE) {
        return -1;
    }

    char response[CHAT_IPC_MAX_RESPONSE];
    int written = snprintf(response,
                           sizeof(response),
                           "MESSAGE %s ",
                           state->ice_peer);
    if (written < 0 || (size_t)written >= sizeof(response)) {
        return -1;
    }

    size_t offset = (size_t)written;
    for (size_t i = 0u; i < plaintext_len; ++i) {
        unsigned char ch = plaintext[i];
        response[offset++] = (ch == '\r' || ch == '\n' || ch == '\0') ? ' ' : (char)ch;
    }
    response[offset++] = '\n';
    response[offset] = '\0';

    return write_ipc_line(state->lookup_client_fd, response);
}

static int decrypt_chat_payload(chatd_state_t *state,
                                chat_packet_type_t type,
                                const unsigned char *payload,
                                size_t payload_len)
{
    unsigned char plaintext[CHAT_MAX_MESSAGE_SIZE];
    size_t plaintext_len = 0u;
    unsigned char tag = 0u;
    chat_crypto_result_t crypto_result =
        chat_crypto_secretstream_decrypt(&state->crypto_stream,
                                          payload,
                                          payload_len,
                                          plaintext,
                                          sizeof(plaintext),
                                          &plaintext_len,
                                          &tag);
    if (crypto_result != CHAT_CRYPTO_OK) {
        chat_log(CHAT_LOG_ERROR, "failed to decrypt chat payload: %s",
                 chat_crypto_result_name(crypto_result));
        return -1;
    }

    if (type == CHAT_PKT_MESSAGE) {
        if (tag != crypto_secretstream_xchacha20poly1305_TAG_MESSAGE) {
            sodium_memzero(plaintext, plaintext_len);
            return -1;
        }
        int delivered = write_chat_message_to_cli(state, plaintext, plaintext_len);
        sodium_memzero(plaintext, plaintext_len);
        return delivered;
    }

    if (type == CHAT_PKT_CLOSE) {
        if (tag != crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
            sodium_memzero(plaintext, plaintext_len);
            return -1;
        }
        chatd_set_session_state(state, CHATD_SESSION_CLOSING);
        sodium_memzero(plaintext, plaintext_len);
        if (state->lookup_client_fd >= 0) {
            char response[CHAT_IPC_MAX_RESPONSE];
            int written = snprintf(response,
                                   sizeof(response),
                                   "CHAT_CLOSED %s\n",
                                   state->ice_peer);
            if (written > 0 && (size_t)written < sizeof(response)) {
                (void)write_ipc_line(state->lookup_client_fd, response);
            }
            close_lookup_client(state);
        }
        reset_ice_session(state);
        chatd_set_session_state(state, CHATD_SESSION_CLOSED);
        return 0;
    }

    sodium_memzero(plaintext, plaintext_len);
    return -1;
}

static int start_crypto_handshake(chatd_state_t *state)
{
    chatd_set_session_state(state, CHATD_SESSION_CRYPTO_HANDSHAKE);

    if (!state->crypto_handshake_sent) {
        chat_crypto_result_t result = chat_crypto_handshake_init(
            &state->crypto_handshake,
            &state->identity,
            state->remote_identity_pk,
            state->crypto_role,
            (const unsigned char *)state->ice_session_id,
            strlen(state->ice_session_id),
            state->crypto_local_handshake_message);
        if (result != CHAT_CRYPTO_OK) {
            chat_log(CHAT_LOG_ERROR, "failed to create crypto handshake: %s",
                     chat_crypto_result_name(result));
            return -1;
        }
    }

    if (send_ice_packet(state,
                        CHAT_PKT_HANDSHAKE,
                        state->crypto_local_handshake_message,
                        sizeof(state->crypto_local_handshake_message)) != 0) {
        return -1;
    }

    state->crypto_next_handshake_at = time(NULL) + 1;
    if (state->crypto_handshake_sent) {
        chat_log(CHAT_LOG_DEBUG, "resent crypto handshake to %s", state->ice_peer);
        return 0;
    }

    state->crypto_handshake_sent = 1;
    chat_log(CHAT_LOG_INFO, "sent crypto handshake to %s", state->ice_peer);
    return 0;
}

static int finish_crypto_handshake(chatd_state_t *state, const unsigned char *payload)
{
    chat_crypto_result_t result = chat_crypto_handshake_finish(&state->crypto_handshake,
                                                              payload,
                                                              &state->crypto_keys);
    if (result != CHAT_CRYPTO_OK) {
        chat_log(CHAT_LOG_ERROR, "failed to verify crypto handshake: %s",
                 chat_crypto_result_name(result));
        return -1;
    }

    state->crypto_keys_ready = 1;
    chat_log(CHAT_LOG_INFO, "crypto session keys established with %s", state->ice_peer);
    return 0;
}

static int send_stream_header(chatd_state_t *state)
{
    if (!state->crypto_stream_header_sent) {
        chat_crypto_result_t result =
            chat_crypto_secretstream_init_push(&state->crypto_stream,
                                               state->crypto_keys.tx,
                                               state->crypto_local_stream_header);
        if (result != CHAT_CRYPTO_OK) {
            chat_log(CHAT_LOG_ERROR, "failed to initialize TX secretstream: %s",
                     chat_crypto_result_name(result));
            return -1;
        }
    }

    if (send_ice_packet(state,
                        CHAT_PKT_STREAM_HEADER,
                        state->crypto_local_stream_header,
                        sizeof(state->crypto_local_stream_header)) != 0) {
        return -1;
    }

    state->crypto_next_stream_header_at = time(NULL) + 1;
    if (state->crypto_stream_header_sent) {
        chat_log(CHAT_LOG_DEBUG, "resent secretstream header to %s", state->ice_peer);
        return 0;
    }

    state->crypto_stream_header_sent = 1;
    chat_log(CHAT_LOG_INFO, "sent secretstream header to %s", state->ice_peer);
    return 0;
}

static int receive_stream_header(chatd_state_t *state, const unsigned char *payload)
{
    chat_crypto_result_t result = chat_crypto_secretstream_init_pull(&state->crypto_stream,
                                                                    state->crypto_keys.rx,
                                                                    payload);
    if (result != CHAT_CRYPTO_OK) {
        chat_log(CHAT_LOG_ERROR, "failed to initialize RX secretstream: %s",
                 chat_crypto_result_name(result));
        return -1;
    }

    state->crypto_stream_header_received = 1;
    chat_log(CHAT_LOG_INFO, "received secretstream header from %s", state->ice_peer);
    return 0;
}

static int handle_ice_app_packet(chatd_state_t *state,
                                 const unsigned char *packet,
                                 size_t packet_len)
{
    chat_packet_header_t header;
    chat_protocol_result_t protocol_result =
        chat_packet_decode_header(packet, packet_len, &header);
    if (protocol_result != CHAT_PROTOCOL_OK) {
        chat_log(CHAT_LOG_ERROR, "invalid ICE application packet: %s",
                 chat_protocol_result_name(protocol_result));
        return -1;
    }

    if (packet_len != CHAT_PACKET_HEADER_SIZE + (size_t)header.length) {
        chat_log(CHAT_LOG_ERROR, "ICE application packet length mismatch");
        return -1;
    }

    const unsigned char *payload = &packet[CHAT_PACKET_HEADER_SIZE];
    if (header.type == CHAT_PKT_HANDSHAKE) {
        if (state->session_state != CHATD_SESSION_ICE_CONNECTED
            && state->session_state != CHATD_SESSION_CRYPTO_HANDSHAKE
            && !(state->session_state == CHATD_SESSION_SECURE && state->crypto_keys_ready)) {
            chat_log(CHAT_LOG_WARN,
                     "rejected HANDSHAKE packet in %s state",
                     chatd_session_state_name(state->session_state));
            return -1;
        }
        if (header.length != CHAT_CRYPTO_KX_MESSAGE_BYTES) {
            return -1;
        }
        if (state->crypto_keys_ready) {
            chat_log(CHAT_LOG_DEBUG, "ignored duplicate crypto handshake from %s", state->ice_peer);
            return 0;
        }
        return finish_crypto_handshake(state, payload);
    }

    if (header.type == CHAT_PKT_STREAM_HEADER) {
        if (state->session_state != CHATD_SESSION_CRYPTO_HANDSHAKE
            && !(state->session_state == CHATD_SESSION_SECURE
                 && state->crypto_stream_header_received)) {
            chat_log(CHAT_LOG_WARN,
                     "rejected STREAM_HEADER packet in %s state",
                     chatd_session_state_name(state->session_state));
            return -1;
        }
        if (header.length != CHAT_CRYPTO_STREAM_HEADER_BYTES) {
            return -1;
        }
        if (!state->crypto_keys_ready) {
            chat_log(CHAT_LOG_DEBUG, "ignored early secretstream header from %s", state->ice_peer);
            return 0;
        }
        if (state->crypto_stream_header_received) {
            chat_log(CHAT_LOG_DEBUG, "ignored duplicate secretstream header from %s", state->ice_peer);
            return 0;
        }
        return receive_stream_header(state, payload);
    }

    if (header.type == CHAT_PKT_MESSAGE || header.type == CHAT_PKT_CLOSE) {
        if (state->session_state != CHATD_SESSION_SECURE
            || !state->encrypted_session_ready
            || header.length < CHAT_CRYPTO_STREAM_ABYTES) {
            chat_log(CHAT_LOG_WARN,
                     "rejected encrypted chat packet in %s state",
                     chatd_session_state_name(state->session_state));
            return -1;
        }
        return decrypt_chat_payload(state, header.type, payload, header.length);
    }

    chat_log(CHAT_LOG_WARN, "unexpected ICE packet type before chat session: %u",
             (unsigned int)header.type);
    return -1;
}

static int process_received_ice_packet(chatd_state_t *state)
{
    unsigned char packet[CHATD_ICE_PACKET_MAX];
    size_t packet_len = 0u;
    chat_ice_result_t result = chat_ice_take_received(&state->ice,
                                                      packet,
                                                      sizeof(packet),
                                                      &packet_len);
    if (result != CHAT_ICE_OK) {
        chat_log(CHAT_LOG_ERROR, "failed to read ICE packet: %s",
                 chat_ice_result_name(result));
        return -1;
    }

    if (packet_len == 0u) {
        return 0;
    }

    int handled = handle_ice_app_packet(state, packet, packet_len);
    sodium_memzero(packet, packet_len);
    return handled;
}

static void service_crypto_session(chatd_state_t *state)
{
    if (!state->ice.ready) {
        return;
    }

    if (state->encrypted_session_ready) {
        for (size_t i = 0u; i < CHAT_ICE_RECV_QUEUE_CAPACITY; ++i) {
            if (process_received_ice_packet(state) != 0) {
                if (state->ice_active) {
                    fail_chat_session(state);
                }
                return;
            }
        }
        return;
    }

    time_t now = time(NULL);

    if (!state->has_remote_identity_pk) {
        fail_chat_session(state);
        return;
    }

    if (state->crypto_deadline_at != 0 && now >= state->crypto_deadline_at) {
        chat_log(CHAT_LOG_WARN, "crypto handshake timed out with %s", state->ice_peer);
        fail_chat_session(state);
        return;
    }

    if (!state->crypto_handshake_sent
        || (!state->crypto_stream_header_received && now >= state->crypto_next_handshake_at)) {
        if (start_crypto_handshake(state) != 0) {
            fail_chat_session(state);
            return;
        }
    }

    if (process_received_ice_packet(state) != 0) {
        fail_chat_session(state);
        return;
    }

    if (state->crypto_keys_ready
        && (!state->crypto_stream_header_sent
            || (!state->encrypted_session_ready && now >= state->crypto_next_stream_header_at))) {
        if (send_stream_header(state) != 0) {
            fail_chat_session(state);
            return;
        }
    }

    if (process_received_ice_packet(state) != 0) {
        fail_chat_session(state);
        return;
    }

    if (state->crypto_keys_ready
        && state->crypto_stream_header_sent
        && state->crypto_stream_header_received) {
        state->encrypted_session_ready = 1;
        chatd_set_session_state(state, CHATD_SESSION_SECURE);
        chat_log(CHAT_LOG_INFO, "encrypted session established with %s", state->ice_peer);
        if (state->lookup_client_fd >= 0) {
            char response[CHAT_IPC_MAX_RESPONSE];
            int written = snprintf(response,
                                   sizeof(response),
                                   "ENCRYPTED_SESSION %s %s\n",
                                   state->ice_peer,
                                   state->ice_selected_pair_is_relayed ? "relay" : "direct");
            if (written > 0 && (size_t)written < sizeof(response)) {
                (void)write_ipc_line(state->lookup_client_fd, response);
            }
        }
    }
}

static void service_ice_session(chatd_state_t *state)
{
    if (!state->ice_active) {
        return;
    }

    chat_ice_poll();
    time_t now = time(NULL);

    if (state->crypto_deadline_at != 0
        && !state->encrypted_session_ready
        && now >= state->crypto_deadline_at) {
        chat_log(CHAT_LOG_WARN, "crypto handshake timed out with %s", state->ice_peer);
        fail_chat_session(state);
        return;
    }

    if (state->ice.gathering_done && state->has_pending_remote_ice_sdp) {
        if (apply_remote_ice_sdp(state, state->ice_peer, state->pending_remote_ice_sdp) != 0) {
            fail_chat_session(state);
            return;
        }
        state->pending_remote_ice_sdp[0] = '\0';
        state->has_pending_remote_ice_sdp = 0;
    }

    if (state->ice.gathering_done
        && !state->ice_local_sdp_sent
        && state->control_wsi != NULL
        && !has_pending_control_message(state)) {
        if (queue_local_ice_sdp(state->control_wsi, state) != 0 && state->pending_len == 0u) {
            fail_chat_session(state);
            return;
        }
    }

    if (state->ice.failed) {
        chat_log(CHAT_LOG_WARN, "ICE failed with %s", state->ice_peer);
        fail_chat_session(state);
        return;
    }

    if (state->ice.ready) {
        if (!state->ice_cli_notified) {
            chat_log(CHAT_LOG_INFO, "ICE connected with %s", state->ice_peer);
            int is_relayed = 0;
            if (chat_ice_selected_pair_is_relayed(&state->ice, &is_relayed)) {
                state->ice_selected_pair_is_relayed = is_relayed;
                chat_log(CHAT_LOG_INFO,
                         "ICE network mode with %s: %s",
                         state->ice_peer,
                         is_relayed ? "TURN relay" : "direct P2P");
            }
            state->ice_cli_notified = 1;
            state->crypto_deadline_at = time(NULL) + CHATD_CRYPTO_TIMEOUT_SECONDS;
            chatd_set_session_state(state, CHATD_SESSION_ICE_CONNECTED);
        }
        service_crypto_session(state);
        return;
    }

    if (now >= state->ice_deadline_at) {
        chat_log(CHAT_LOG_WARN, "ICE failed with %s", state->ice_peer);
        fail_chat_session(state);
    }
}

static int handle_chat_request(struct lws *wsi, chatd_state_t *state, const char *json)
{
    char from[CHAT_USERNAME_MAX_LEN + 1u];
    char to[CHAT_USERNAME_MAX_LEN + 1u];
    char session_id[CHATD_SESSION_ID_HEX_LEN];
    char public_key_hex[CHATD_HEX_PUBLIC_KEY_LEN];
    unsigned char remote_identity_pk[crypto_sign_PUBLICKEYBYTES];

    if (!json_get_string(json, "from", from, sizeof(from))
        || !json_get_string(json, "to", to, sizeof(to))
        || !json_get_string(json, "session_id", session_id, sizeof(session_id))
        || !json_get_string(json, "public_key", public_key_hex, sizeof(public_key_hex))
        || strcmp(to, state->identity.username) != 0
        || !chat_username_is_valid(from)
        || session_id[0] == '\0'
        || !hex_to_bin(public_key_hex, remote_identity_pk, sizeof(remote_identity_pk))) {
        chat_log(CHAT_LOG_WARN, "invalid chat_request received");
        return 0;
    }

    int is_new_contact = 0;
    chat_contacts_result_t contact_result =
        chat_contacts_verify_or_pin(from, remote_identity_pk, &is_new_contact);
    if (contact_result != CHAT_CONTACTS_OK) {
        chat_log(CHAT_LOG_ERROR,
                 "rejected chat_request from %s: %s",
                 from,
                 chat_contacts_result_name(contact_result));
        sodium_memzero(remote_identity_pk, sizeof(remote_identity_pk));
        return 0;
    }
    if (is_new_contact) {
        char fingerprint[CHAT_IDENTITY_FINGERPRINT_LEN];
        if (chat_identity_fingerprint(remote_identity_pk, fingerprint, sizeof(fingerprint))
            == CHAT_IDENTITY_OK) {
            chat_log(CHAT_LOG_INFO, "pinned new contact %s (%s)", from, fingerprint);
        }
    }

    chat_log(CHAT_LOG_INFO, "incoming chat request from %s", from);
    chatd_set_session_state(state, CHATD_SESSION_REQUESTING);
    int result = queue_chat_accept(wsi, state, from, session_id);
    if (result != 0) {
        sodium_memzero(remote_identity_pk, sizeof(remote_identity_pk));
        return result;
    }

    if (begin_ice_session(wsi, state, from, session_id, 0, remote_identity_pk) != 0) {
        chat_log(CHAT_LOG_ERROR, "could not prepare ICE for incoming chat");
    }

    sodium_memzero(remote_identity_pk, sizeof(remote_identity_pk));
    return 0;
}

static void close_lookup_client(chatd_state_t *state)
{
    if (state->lookup_client_fd >= 0) {
        (void)close(state->lookup_client_fd);
        state->lookup_client_fd = -1;
    }
    state->lookup_peer[0] = '\0';
    state->chat_retry_count = 0;
}

static void write_lookup_response(chatd_state_t *state, const char *prefix, const char *username)
{
    if (state->lookup_client_fd < 0) {
        return;
    }

    char response[CHAT_IPC_MAX_RESPONSE];
    int written = snprintf(response, sizeof(response), "%s %s\n", prefix, username);
    if (written > 0 && (size_t)written < sizeof(response)) {
        (void)write_ipc_line(state->lookup_client_fd, response);
    }

    close_lookup_client(state);
}

static int handle_user_status(chatd_state_t *state, const char *json)
{
    if (state->lookup_client_fd < 0) {
        return 0;
    }

    char username[CHAT_USERNAME_MAX_LEN + 1u];
    if (!json_get_string(json, "username", username, sizeof(username))
        || strcmp(username, state->lookup_peer) != 0) {
        return 0;
    }

    int known = json_bool_is_true(json, "known");
    int online = json_bool_is_true(json, "online");
    if (!known || !online) {
        chat_log(CHAT_LOG_INFO, "lookup result: %s offline", username);
        write_lookup_response(state, "USER_OFFLINE", username);
        return 0;
    }

    chat_log(CHAT_LOG_INFO, "lookup result: %s online", username);
    write_lookup_response(state, "USER_ONLINE", username);
    return 0;
}

static int handle_receive(struct lws *wsi, chatd_state_t *state, const char *json)
{
    char type[32];
    if (!json_get_string(json, "type", type, sizeof(type))) {
        chat_log(CHAT_LOG_WARN, "server message without type");
        return 0;
    }

    if (strcmp(type, "error") == 0) {
        char code[128];
        if (!json_get_string(json, "code", code, sizeof(code))) {
            (void)snprintf(code, sizeof(code), "unknown");
        }

        if (state->phase == CHATD_PHASE_REGISTER && strcmp(code, "user already exists") == 0) {
            state->phase = CHATD_PHASE_HELLO;
            return queue_hello(wsi, state);
        }

        if (state->lookup_client_fd >= 0 && strcmp(code, "peer_offline") == 0) {
            write_lookup_response(state, "USER_OFFLINE", state->lookup_peer);
            return 0;
        }

        if (state->lookup_client_fd >= 0) {
            write_lookup_response(state, "ERROR", code);
        }

        chat_log(CHAT_LOG_ERROR, "control server error: %s", code);
        state->phase = CHATD_PHASE_FAILED;
        return -1;
    }

    if (state->phase == CHATD_PHASE_REGISTER && strcmp(type, "register_ok") == 0) {
        state->phase = CHATD_PHASE_HELLO;
        return queue_hello(wsi, state);
    }

    if (state->phase == CHATD_PHASE_HELLO && strcmp(type, "auth_challenge") == 0) {
        char challenge_hex[CHATD_HEX_CHALLENGE_LEN];
        if (!json_get_string(json, "challenge", challenge_hex, sizeof(challenge_hex))
            || !hex_to_bin(challenge_hex, state->challenge, sizeof(state->challenge))) {
            chat_log(CHAT_LOG_ERROR, "invalid auth challenge from server");
            state->phase = CHATD_PHASE_FAILED;
            return -1;
        }

        state->has_challenge = 1;
        state->phase = CHATD_PHASE_AUTH_RESPONSE;
        return queue_auth_response(wsi, state);
    }

    if (state->phase == CHATD_PHASE_AUTH_RESPONSE && strcmp(type, "auth_ok") == 0) {
        sodium_memzero(state->challenge, sizeof(state->challenge));
        state->has_challenge = 0;
        state->phase = CHATD_PHASE_ONLINE;
        chat_log(CHAT_LOG_INFO, "%s is online", state->identity.username);
        return 0;
    }

    if (strcmp(type, "user_status") == 0) {
        return handle_user_status(state, json);
    }

    if (strcmp(type, "chat_request") == 0) {
        return handle_chat_request(wsi, state, json);
    }

    if (strcmp(type, "chat_accept") == 0) {
        char from[CHAT_USERNAME_MAX_LEN + 1u];
        char to[CHAT_USERNAME_MAX_LEN + 1u];
        char session_id[CHATD_SESSION_ID_HEX_LEN];
        char public_key_hex[CHATD_HEX_PUBLIC_KEY_LEN];
        unsigned char remote_identity_pk[crypto_sign_PUBLICKEYBYTES];
        int has_remote_identity_pk =
            json_get_string(json, "public_key", public_key_hex, sizeof(public_key_hex))
            && hex_to_bin(public_key_hex, remote_identity_pk, sizeof(remote_identity_pk));
        if (json_get_string(json, "from", from, sizeof(from))
            && json_get_string(json, "to", to, sizeof(to))
            && json_get_string(json, "session_id", session_id, sizeof(session_id))
            && has_remote_identity_pk
            && state->lookup_client_fd >= 0
            && strcmp(from, state->lookup_peer) == 0
            && strcmp(to, state->identity.username) == 0
            && strcmp(session_id, state->ice_session_id) == 0) {
            int is_new_contact = 0;
            chat_contacts_result_t contact_result =
                chat_contacts_verify_or_pin(from, remote_identity_pk, &is_new_contact);
            if (contact_result == CHAT_CONTACTS_ERR_MISMATCH) {
                chat_log(CHAT_LOG_ERROR, "identity mismatch for %s", from);
                if (queue_chat_cancel(wsi, state, from, session_id) != 0) {
                    chat_log(CHAT_LOG_WARN, "failed to cancel mismatched session with %s", from);
                }
                write_lookup_response(state, "IDENTITY_MISMATCH", from);
            } else if (contact_result != CHAT_CONTACTS_OK) {
                chat_log(CHAT_LOG_ERROR,
                         "failed to verify identity for %s: %s",
                         from,
                         chat_contacts_result_name(contact_result));
                write_lookup_response(state, "ERROR", "contact_verification_failed");
            } else {
                if (is_new_contact) {
                    char fingerprint[CHAT_IDENTITY_FINGERPRINT_LEN];
                    if (chat_identity_fingerprint(remote_identity_pk, fingerprint, sizeof(fingerprint))
                        == CHAT_IDENTITY_OK) {
                        chat_log(CHAT_LOG_INFO, "pinned new contact %s (%s)", from, fingerprint);
                    }
                }
                if (begin_ice_session(wsi, state, from, session_id, 1, remote_identity_pk) != 0) {
                    write_lookup_response(state, "ICE_FAILED", from);
                }
            }
        }
        if (has_remote_identity_pk) {
            sodium_memzero(remote_identity_pk, sizeof(remote_identity_pk));
        }
        chat_log(CHAT_LOG_INFO, "received signaling message: %s", type);
        return 0;
    }

    if (strcmp(type, "ice_credentials") == 0) {
        return handle_ice_credentials(state, json);
    }

    if (strcmp(type, "chat_cancel") == 0) {
        char from[CHAT_USERNAME_MAX_LEN + 1u];
        char to[CHAT_USERNAME_MAX_LEN + 1u];
        char session_id[CHATD_SESSION_ID_HEX_LEN];
        if (state->ice_active
            && json_get_string(json, "from", from, sizeof(from))
            && json_get_string(json, "to", to, sizeof(to))
            && json_get_string(json, "session_id", session_id, sizeof(session_id))
            && strcmp(from, state->ice_peer) == 0
            && strcmp(to, state->identity.username) == 0
            && strcmp(session_id, state->ice_session_id) == 0) {
            chat_log(CHAT_LOG_INFO, "chat session cancelled by %s", from);
            reset_ice_session(state);
            chatd_set_session_state(state, CHATD_SESSION_CLOSED);
        } else {
            chat_log(CHAT_LOG_WARN, "ignored invalid chat_cancel message");
        }
        return 0;
    }

    if (strcmp(type, "chat_reject") == 0
        || strcmp(type, "ice_candidate") == 0
        || strcmp(type, "ice_done") == 0
        || strcmp(type, "ice_gathering_done") == 0
        || strcmp(type, "chat_end") == 0) {
        chat_log(CHAT_LOG_INFO, "received signaling message: %s", type);
        return 0;
    }

    chat_log(CHAT_LOG_DEBUG, "ignored server message in current state: %s", type);
    return 0;
}

static int callback_chatd_control(struct lws *wsi,
                                  enum lws_callback_reasons reason,
                                  void *user,
                                  void *in,
                                  size_t len)
{
    chatd_state_t *state = user;

    switch (reason) {
    case LWS_CALLBACK_CLIENT_ESTABLISHED:
        state->control_wsi = wsi;
        state->connected = 1;
        state->phase = CHATD_PHASE_REGISTER;
        chat_log(CHAT_LOG_INFO, "connected to control server");
        return queue_register(wsi, state);

    case LWS_CALLBACK_CLIENT_RECEIVE: {
        if (len >= CHATD_MAX_JSON_SIZE
            || lws_remaining_packet_payload(wsi) != 0
            || !lws_is_final_fragment(wsi)) {
            chat_log(CHAT_LOG_ERROR, "oversized or fragmented server message");
            state->phase = CHATD_PHASE_FAILED;
            return -1;
        }

        char json[CHATD_MAX_JSON_SIZE];
        memcpy(json, in, len);
        json[len] = '\0';
        return handle_receive(wsi, state, json);
    }

    case LWS_CALLBACK_CLIENT_WRITEABLE:
        pthread_mutex_lock(&state->lock);
        size_t pending_len = state->pending_len;
        if (pending_len == 0u) {
            pthread_mutex_unlock(&state->lock);
            return 0;
        }

        if (lws_write(wsi,
                      &state->pending[LWS_PRE],
                      pending_len,
                      LWS_WRITE_TEXT) < (int)pending_len) {
            pthread_mutex_unlock(&state->lock);
            state->phase = CHATD_PHASE_FAILED;
            return -1;
        }
        state->pending_len = 0u;
        pthread_mutex_unlock(&state->lock);
        return 0;

    case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
        chat_log(CHAT_LOG_WARN, "control server connection attempt reported an error");
        state->control_wsi = NULL;
        state->connected = 0;
        state->should_reconnect = 1;
        state->next_reconnect_at = time(NULL) + CHATD_RECONNECT_SECONDS;
        if (state->lookup_client_fd >= 0 && !state->encrypted_session_ready) {
            write_lookup_response(state, "ERROR", "server_unavailable");
        }
        return 0;

    case LWS_CALLBACK_CLIENT_CLOSED:
        chat_log(CHAT_LOG_WARN, "control server connection closed");
        state->control_wsi = NULL;
        state->connected = 0;
        state->should_reconnect = 1;
        state->next_reconnect_at = time(NULL) + CHATD_RECONNECT_SECONDS;
        if (state->lookup_client_fd >= 0 && !state->encrypted_session_ready) {
            write_lookup_response(state, "ERROR", "server_disconnected");
        }
        if (state->has_challenge) {
            sodium_memzero(state->challenge, sizeof(state->challenge));
            state->has_challenge = 0;
        }
        return 0;

    default:
        return 0;
    }
}

static int parse_server_url(char *url,
                            const char **protocol,
                            const char **address,
                            int *port,
                            const char **path)
{
    if (lws_parse_uri(url, protocol, address, port, path) != 0) {
        return -1;
    }

    if (strcmp(*protocol, "ws") != 0 && strcmp(*protocol, "wss") != 0) {
        return -1;
    }

    return 0;
}

static struct lws *connect_control_server(struct lws_context *context,
                                          const char *protocol,
                                          const char *address,
                                          int port,
                                          const char *path,
                                          chatd_state_t *state)
{
    struct lws_client_connect_info connect_info;
    memset(&connect_info, 0, sizeof(connect_info));
    connect_info.context = context;
    connect_info.address = address;
    connect_info.port = port;
    connect_info.path = path;
    connect_info.host = address;
    connect_info.origin = address;
    connect_info.protocol = CHATD_CONTROL_PROTOCOL;
    connect_info.local_protocol_name = CHATD_CONTROL_PROTOCOL;
    connect_info.ietf_version_or_minus_one = -1;
    connect_info.userdata = state;
    connect_info.ssl_connection = strcmp(protocol, "wss") == 0 ? LCCSCF_USE_SSL : 0;

    state->should_reconnect = 0;
    return lws_client_connect_via_info(&connect_info);
}

static int start_ipc_server(chatd_state_t *state)
{
    if (chat_ipc_socket_path(state->ipc_socket_path, sizeof(state->ipc_socket_path)) != CHAT_IPC_OK) {
        chat_log(CHAT_LOG_ERROR, "failed to resolve IPC socket path");
        return -1;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        chat_log(CHAT_LOG_ERROR, "failed to create IPC socket: %s", strerror(errno));
        return -1;
    }

    (void)unlink(state->ipc_socket_path);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    int copied = snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", state->ipc_socket_path);
    if (copied < 0 || (size_t)copied >= sizeof(addr.sun_path)) {
        chat_log(CHAT_LOG_ERROR, "IPC socket path is too long");
        (void)close(fd);
        return -1;
    }

    if (bind(fd, (const struct sockaddr *)&addr, sizeof(addr)) != 0) {
        chat_log(CHAT_LOG_ERROR, "failed to bind IPC socket: %s", strerror(errno));
        (void)close(fd);
        return -1;
    }

    (void)chmod(state->ipc_socket_path, 0600);

    if (listen(fd, 16) != 0) {
        chat_log(CHAT_LOG_ERROR, "failed to listen on IPC socket: %s", strerror(errno));
        (void)close(fd);
        (void)unlink(state->ipc_socket_path);
        return -1;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        (void)fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }

    state->ipc_fd = fd;
    chat_log(CHAT_LOG_INFO, "IPC listening on %s", state->ipc_socket_path);
    return 0;
}

static void write_ipc_status(int client_fd, const chatd_state_t *state)
{
    const char *status = "OFFLINE";
    char username[CHAT_USERNAME_MAX_LEN + 1u];

    pthread_mutex_lock((pthread_mutex_t *)&state->lock);
    if (state->phase == CHATD_PHASE_ONLINE) {
        status = "ONLINE";
    } else if (state->connected) {
        status = "CONNECTING";
    }
    (void)snprintf(username, sizeof(username), "%s", state->identity.username);
    pthread_mutex_unlock((pthread_mutex_t *)&state->lock);

    char response[CHAT_IPC_MAX_RESPONSE];
    int written = snprintf(response,
                           sizeof(response),
                           "%s %s\n",
                           status,
                           username);
    if (written < 0 || (size_t)written >= sizeof(response)) {
        return;
    }

    (void)write_ipc_line(client_fd, response);
}

static int handle_open_chat_command(int client_fd, chatd_state_t *state, const char *peer)
{
    if (!chat_username_is_valid(peer)) {
        const char response[] = "ERROR invalid_username\n";
        (void)write_ipc_line(client_fd, response);
        return 0;
    }

    pthread_mutex_lock(&state->lock);
    int online = state->phase == CHATD_PHASE_ONLINE && state->control_wsi != NULL;
    int is_self = strcmp(peer, state->identity.username) == 0;
    pthread_mutex_unlock(&state->lock);

    if (!online) {
        const char response[] = "ERROR daemon_not_online\n";
        (void)write_ipc_line(client_fd, response);
        return 0;
    }

    if (is_self) {
        char response[CHAT_IPC_MAX_RESPONSE];
        int written = snprintf(response, sizeof(response), "USER_ONLINE %s\n", peer);
        if (written > 0 && (size_t)written < sizeof(response)) {
            (void)write_ipc_line(client_fd, response);
        }
        return 0;
    }

    if (state->ice_active
        && state->encrypted_session_ready
        && strcmp(peer, state->ice_peer) == 0
        && state->lookup_client_fd < 0) {
        state->lookup_client_fd = client_fd;
        int flags = fcntl(client_fd, F_GETFL, 0);
        if (flags >= 0) {
            (void)fcntl(client_fd, F_SETFL, flags | O_NONBLOCK);
        }

        char response[CHAT_IPC_MAX_RESPONSE];
        int written = snprintf(response,
                               sizeof(response),
                               "ENCRYPTED_SESSION %s %s\n",
                               state->ice_peer,
                               state->ice_selected_pair_is_relayed ? "relay" : "direct");
        if (written > 0 && (size_t)written < sizeof(response)) {
            (void)write_ipc_line(client_fd, response);
        }
        return 1;
    }

    if (state->lookup_client_fd >= 0 || has_pending_control_message(state)) {
        const char response[] = "ERROR busy\n";
        (void)write_ipc_line(client_fd, response);
        return 0;
    }

    int copied = snprintf(state->lookup_peer, sizeof(state->lookup_peer), "%s", peer);
    if (copied < 0 || (size_t)copied >= sizeof(state->lookup_peer)) {
        const char response[] = "ERROR invalid_username\n";
        (void)write_ipc_line(client_fd, response);
        return 0;
    }

    state->lookup_client_fd = client_fd;
    state->chat_retry_count = 0;
    chatd_set_session_state(state, CHATD_SESSION_REQUESTING);
    int flags = fcntl(client_fd, F_GETFL, 0);
    if (flags >= 0) {
        (void)fcntl(client_fd, F_SETFL, flags | O_NONBLOCK);
    }
    if (queue_chat_request(state->control_wsi,
                           state,
                           peer,
                           state->ice_session_id) != 0) {
        write_lookup_response(state, "ERROR", "chat_request_failed");
        return 0;
    }

    return 1;
}

static void service_active_chat_client(chatd_state_t *state)
{
    if (state->lookup_client_fd < 0 || !state->encrypted_session_ready) {
        return;
    }

    char command[CHAT_IPC_MAX_COMMAND];
    ssize_t bytes_read = read(state->lookup_client_fd, command, sizeof(command) - 1u);
    if (bytes_read < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return;
        }
        close_lookup_client(state);
        reset_ice_session(state);
        chatd_set_session_state(state, CHATD_SESSION_FAILED);
        return;
    }

    if (bytes_read == 0) {
        (void)send_encrypted_chat_close(state);
        close_lookup_client(state);
        reset_ice_session(state);
        chatd_set_session_state(state, CHATD_SESSION_CLOSED);
        return;
    }

    command[bytes_read] = '\0';
    char *cursor = command;
    const char prefix[] = "SEND_MESSAGE ";
    size_t prefix_len = sizeof(prefix) - 1u;
    while (*cursor != '\0' && state->lookup_client_fd >= 0 && state->ice_active) {
        char *line_end = strpbrk(cursor, "\r\n");
        if (line_end != NULL) {
            *line_end = '\0';
        }

        if (strcmp(cursor, "CLOSE_CHAT") == 0) {
            (void)send_encrypted_chat_close(state);
            close_lookup_client(state);
            reset_ice_session(state);
            chatd_set_session_state(state, CHATD_SESSION_CLOSED);
            sodium_memzero(command, sizeof(command));
            return;
        }

        if (strncmp(cursor, prefix, prefix_len) == 0) {
            char *text = &cursor[prefix_len];
            size_t text_len = strlen(text);
            if (send_encrypted_chat_message(state, text, text_len) != 0) {
                (void)write_ipc_line(state->lookup_client_fd, "ERROR send_failed\n");
            }
        } else if (*cursor != '\0') {
            (void)write_ipc_line(state->lookup_client_fd, "ERROR unknown_command\n");
        }

        if (line_end == NULL) {
            break;
        }
        cursor = line_end + 1;
        while (*cursor == '\r' || *cursor == '\n') {
            ++cursor;
        }
    }
    sodium_memzero(command, sizeof(command));
}

static int handle_ipc_client(int client_fd, chatd_state_t *state)
{
    char command[CHAT_IPC_MAX_COMMAND];
    ssize_t bytes_read = read(client_fd, command, sizeof(command) - 1u);
    if (bytes_read <= 0) {
        return 0;
    }

    command[bytes_read] = '\0';
    if (strcmp(command, "STATUS\n") == 0 || strcmp(command, "STATUS") == 0) {
        write_ipc_status(client_fd, state);
        return 0;
    }

    char peer[CHAT_USERNAME_MAX_LEN + 2u];
    if (sscanf(command, "OPEN_CHAT %33s", peer) == 1) {
        return handle_open_chat_command(client_fd, state, peer);
    }

    const char response[] = "ERROR unknown_command\n";
    (void)write_ipc_line(client_fd, response);
    return 0;
}

static void service_ipc(chatd_state_t *state)
{
    if (state->pending_ipc_client_fd < 0) {
        int client_fd = accept(state->ipc_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return;
            }
            if (g_interrupted && (errno == EBADF || errno == EINVAL)) {
                return;
            }
            chat_log(CHAT_LOG_WARN, "IPC accept failed: %s", strerror(errno));
            return;
        }

        state->pending_ipc_client_fd = client_fd;
        state->pending_ipc_deadline_at = time(NULL) + 5;
    }

    struct pollfd pfd = {
        .fd = state->pending_ipc_client_fd,
        .events = POLLIN,
        .revents = 0
    };
    int ready = poll(&pfd, 1u, 0);
    if (ready < 0 || (ready > 0 && (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0)
        || time(NULL) >= state->pending_ipc_deadline_at) {
        (void)close(state->pending_ipc_client_fd);
        state->pending_ipc_client_fd = -1;
        state->pending_ipc_deadline_at = 0;
        return;
    }
    if (ready == 0 || (pfd.revents & POLLIN) == 0) {
        return;
    }

    int client_fd = state->pending_ipc_client_fd;
    state->pending_ipc_client_fd = -1;
    state->pending_ipc_deadline_at = 0;
    int keep_open = handle_ipc_client(client_fd, state);
    if (!keep_open) {
        (void)close(client_fd);
    }
}

static void *service_wakeup_thread_main(void *user_data)
{
    chatd_state_t *state = user_data;
    while (!g_interrupted) {
        if (state->context != NULL) {
            lws_cancel_service(state->context);
        }
        struct timespec sleep_time = {.tv_sec = 0, .tv_nsec = 10 * 1000 * 1000};
        (void)nanosleep(&sleep_time, NULL);
    }
    return NULL;
}

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    if (sodium_init() < 0) {
        chat_log(CHAT_LOG_ERROR, "libsodium initialization failed");
        return 1;
    }

    chatd_state_t state;
    memset(&state, 0, sizeof(state));
    state.ipc_fd = -1;
    state.pending_ipc_client_fd = -1;
    state.lookup_client_fd = -1;
    chat_ice_session_init(&state.ice);
    if (load_ice_config(&state.ice_config) != 0) {
        chat_log(CHAT_LOG_ERROR, "invalid ICE configuration in config.toml");
        return 1;
    }
    if (pthread_mutex_init(&state.lock, NULL) != 0) {
        chat_log(CHAT_LOG_ERROR, "failed to initialize daemon lock");
        sodium_memzero(&state.ice_config, sizeof(state.ice_config));
        return 1;
    }
    chat_identity_result_t identity_result = chat_identity_load(&state.identity);
    if (identity_result != CHAT_IDENTITY_OK) {
        chat_log(CHAT_LOG_ERROR, "failed to load identity: %s",
                 chat_identity_result_name(identity_result));
        wipe_ice_config(&state.ice_config);
        pthread_mutex_destroy(&state.lock);
        return 1;
    }

    char server_url[CHAT_IDENTITY_SERVER_URL_MAX];
    identity_result = chat_identity_load_server_url(server_url, sizeof(server_url));
    if (identity_result != CHAT_IDENTITY_OK) {
        chat_log(CHAT_LOG_ERROR, "failed to load server_url: %s",
                 chat_identity_result_name(identity_result));
        chat_identity_wipe(&state.identity);
        wipe_ice_config(&state.ice_config);
        pthread_mutex_destroy(&state.lock);
        return 1;
    }

    char server_url_for_log[CHAT_IDENTITY_SERVER_URL_MAX];
    int copied = snprintf(server_url_for_log, sizeof(server_url_for_log), "%s", server_url);
    if (copied < 0 || (size_t)copied >= sizeof(server_url_for_log)) {
        chat_log(CHAT_LOG_ERROR, "server_url is too long");
        chat_identity_wipe(&state.identity);
        wipe_ice_config(&state.ice_config);
        pthread_mutex_destroy(&state.lock);
        return 1;
    }

    const char *protocol = NULL;
    const char *address = NULL;
    const char *path = NULL;
    int port = 0;
    if (parse_server_url(server_url, &protocol, &address, &port, &path) != 0) {
        chat_log(CHAT_LOG_ERROR, "invalid server_url");
        chat_identity_wipe(&state.identity);
        wipe_ice_config(&state.ice_config);
        pthread_mutex_destroy(&state.lock);
        return 1;
    }

    struct lws_protocols protocols[] = {
        {
            .name = CHATD_CONTROL_PROTOCOL,
            .callback = callback_chatd_control,
            .per_session_data_size = 0,
            .rx_buffer_size = CHATD_MAX_JSON_SIZE,
            .id = 0,
            .user = NULL,
            .tx_packet_size = CHATD_MAX_JSON_SIZE,
        },
        {0}
    };

    struct lws_context_creation_info info;
    memset(&info, 0, sizeof(info));
    info.port = CONTEXT_PORT_NO_LISTEN;
    info.protocols = protocols;

    lws_set_log_level(LLL_ERR | LLL_WARN, NULL);
    struct lws_context *context = lws_create_context(&info);
    if (context == NULL) {
        chat_log(CHAT_LOG_ERROR, "failed to create libwebsockets context");
        chat_identity_wipe(&state.identity);
        wipe_ice_config(&state.ice_config);
        pthread_mutex_destroy(&state.lock);
        return 1;
    }
    state.context = context;

    if (connect_control_server(context, protocol, address, port, path, &state) == NULL) {
        chat_log(CHAT_LOG_ERROR, "failed to start control server connection");
        lws_context_destroy(context);
        chat_identity_wipe(&state.identity);
        wipe_ice_config(&state.ice_config);
        pthread_mutex_destroy(&state.lock);
        return 1;
    }

    if (start_ipc_server(&state) != 0) {
        lws_context_destroy(context);
        chat_identity_wipe(&state.identity);
        wipe_ice_config(&state.ice_config);
        pthread_mutex_destroy(&state.lock);
        return 1;
    }

    (void)signal(SIGINT, handle_signal);
    (void)signal(SIGTERM, handle_signal);

    if (pthread_create(&state.wakeup_thread, NULL, service_wakeup_thread_main, &state) != 0) {
        chat_log(CHAT_LOG_ERROR, "failed to start service wakeup thread");
        (void)close(state.ipc_fd);
        (void)unlink(state.ipc_socket_path);
        lws_context_destroy(context);
        chat_identity_wipe(&state.identity);
        wipe_ice_config(&state.ice_config);
        pthread_mutex_destroy(&state.lock);
        return 1;
    }
    state.wakeup_thread_started = 1;

    chat_log(CHAT_LOG_INFO, "chatd connecting to %s", server_url_for_log);
    while (!g_interrupted && state.phase != CHATD_PHASE_FAILED) {
        service_ipc(&state);
        service_active_chat_client(&state);
        service_ice_session(&state);
        if (has_pending_control_message(&state) && state.control_wsi != NULL) {
            (void)lws_callback_on_writable_all_protocol(lws_get_context(state.control_wsi),
                                                        lws_get_protocol(state.control_wsi));
            (void)lws_service(context, 0);
        }
        (void)lws_service(context, 0);
        if (state.should_reconnect && !state.connected && time(NULL) >= state.next_reconnect_at) {
            chat_log(CHAT_LOG_INFO, "reconnecting to control server");
            if (connect_control_server(context, protocol, address, port, path, &state) == NULL) {
                state.next_reconnect_at = time(NULL) + CHATD_RECONNECT_SECONDS;
            }
        }

        struct timespec sleep_time = {.tv_sec = 0, .tv_nsec = 10 * 1000 * 1000};
        (void)nanosleep(&sleep_time, NULL);
    }

    g_interrupted = 1;
    if (state.ipc_fd >= 0) {
        (void)shutdown(state.ipc_fd, SHUT_RDWR);
        (void)close(state.ipc_fd);
        (void)unlink(state.ipc_socket_path);
    }
    if (state.wakeup_thread_started) {
        (void)pthread_join(state.wakeup_thread, NULL);
    }
    if (state.pending_ipc_client_fd >= 0) {
        (void)close(state.pending_ipc_client_fd);
    }
    close_lookup_client(&state);
    reset_ice_session(&state);
    lws_context_destroy(context);
    chat_identity_wipe(&state.identity);
    wipe_ice_config(&state.ice_config);
    pthread_mutex_destroy(&state.lock);
    return state.phase == CHATD_PHASE_FAILED ? 1 : 0;
}
