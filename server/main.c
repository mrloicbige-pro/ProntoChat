#include "common/log.h"
#include "server/users.h"

#include <libwebsockets.h>
#include <signal.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHAT_SERVER_DEFAULT_PORT 8787
#define CHAT_SERVER_PROTOCOL_NAME "chat-control-v1"
#define CHAT_SERVER_MAX_JSON_SIZE 4096u
#define CHAT_SERVER_CHALLENGE_BYTES 32u
#define CHAT_SERVER_HEX_PUBLIC_KEY_LEN (crypto_sign_PUBLICKEYBYTES * 2u + 1u)
#define CHAT_SERVER_HEX_SIGNATURE_LEN (crypto_sign_BYTES * 2u + 1u)
#define CHAT_SERVER_HEX_CHALLENGE_LEN (CHAT_SERVER_CHALLENGE_BYTES * 2u + 1u)

typedef struct {
    chat_server_users_t users;
} chat_server_state_t;

typedef struct {
    chat_server_state_t *state;
    char username[CHAT_USERNAME_MAX_LEN + 1u];
    unsigned char challenge[CHAT_SERVER_CHALLENGE_BYTES];
    int has_challenge;
    int authenticated;
    unsigned char pending[LWS_PRE + CHAT_SERVER_MAX_JSON_SIZE];
    size_t pending_len;
} chat_server_session_t;

static volatile sig_atomic_t g_interrupted = 0;

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

static int send_json(struct lws *wsi, chat_server_session_t *session, const char *json)
{
    size_t length = strlen(json);
    if (length >= CHAT_SERVER_MAX_JSON_SIZE) {
        return -1;
    }

    memcpy(&session->pending[LWS_PRE], json, length);
    session->pending_len = length;
    (void)lws_callback_on_writable(wsi);
    return 0;
}

static int send_error(struct lws *wsi, chat_server_session_t *session, const char *code)
{
    char response[256];
    int written = snprintf(response,
                           sizeof(response),
                           "{\"type\":\"error\",\"code\":\"%s\"}",
                           code);
    if (written < 0 || (size_t)written >= sizeof(response)) {
        return -1;
    }

    return send_json(wsi, session, response);
}

static int handle_register(struct lws *wsi, chat_server_session_t *session, const char *json)
{
    char username[CHAT_USERNAME_MAX_LEN + 1u];
    char public_key_hex[CHAT_SERVER_HEX_PUBLIC_KEY_LEN];
    unsigned char public_key[crypto_sign_PUBLICKEYBYTES];

    if (!json_get_string(json, "username", username, sizeof(username))
        || !json_get_string(json, "public_key", public_key_hex, sizeof(public_key_hex))
        || !chat_username_is_valid(username)
        || !hex_to_bin(public_key_hex, public_key, sizeof(public_key))) {
        return send_error(wsi, session, "bad_register");
    }

    chat_server_users_result_t result = chat_server_users_register(&session->state->users,
                                                                   username,
                                                                   public_key);
    sodium_memzero(public_key, sizeof(public_key));
    if (result != CHAT_SERVER_USERS_OK) {
        chat_log(CHAT_LOG_WARN, "registration failed for %s: %s",
                 username, chat_server_users_result_name(result));
        return send_error(wsi, session, chat_server_users_result_name(result));
    }

    chat_log(CHAT_LOG_INFO, "registered user %s", username);
    return send_json(wsi, session, "{\"type\":\"register_ok\"}");
}

static int handle_hello(struct lws *wsi, chat_server_session_t *session, const char *json)
{
    char username[CHAT_USERNAME_MAX_LEN + 1u];
    if (!json_get_string(json, "username", username, sizeof(username))
        || !chat_username_is_valid(username)) {
        return send_error(wsi, session, "bad_hello");
    }

    if (chat_server_users_find(&session->state->users, username) == NULL) {
        return send_error(wsi, session, "unknown_user");
    }

    randombytes_buf(session->challenge, sizeof(session->challenge));
    session->has_challenge = 1;
    session->authenticated = 0;
    (void)snprintf(session->username, sizeof(session->username), "%s", username);

    char challenge_hex[CHAT_SERVER_HEX_CHALLENGE_LEN];
    (void)sodium_bin2hex(challenge_hex,
                         sizeof(challenge_hex),
                         session->challenge,
                         sizeof(session->challenge));

    char response[192];
    int written = snprintf(response,
                           sizeof(response),
                           "{\"type\":\"auth_challenge\",\"challenge\":\"%s\"}",
                           challenge_hex);
    if (written < 0 || (size_t)written >= sizeof(response)) {
        return -1;
    }

    return send_json(wsi, session, response);
}

static int handle_auth_response(struct lws *wsi, chat_server_session_t *session, const char *json)
{
    char signature_hex[CHAT_SERVER_HEX_SIGNATURE_LEN];
    unsigned char signature[crypto_sign_BYTES];

    if (!session->has_challenge || session->username[0] == '\0') {
        return send_error(wsi, session, "auth_not_started");
    }

    if (!json_get_string(json, "signature", signature_hex, sizeof(signature_hex))
        || !hex_to_bin(signature_hex, signature, sizeof(signature))) {
        return send_error(wsi, session, "bad_auth_response");
    }

    const chat_server_user_t *user = chat_server_users_find(&session->state->users,
                                                            session->username);
    if (user == NULL) {
        sodium_memzero(signature, sizeof(signature));
        return send_error(wsi, session, "unknown_user");
    }

    if (crypto_sign_verify_detached(signature,
                                    session->challenge,
                                    sizeof(session->challenge),
                                    user->identity_pk) != 0) {
        sodium_memzero(signature, sizeof(signature));
        return send_error(wsi, session, "authentication_failed");
    }

    sodium_memzero(signature, sizeof(signature));
    sodium_memzero(session->challenge, sizeof(session->challenge));
    session->has_challenge = 0;
    session->authenticated = 1;

    chat_server_users_result_t result = chat_server_users_set_online(&session->state->users,
                                                                     session->username,
                                                                     wsi);
    if (result != CHAT_SERVER_USERS_OK) {
        session->authenticated = 0;
        return send_error(wsi, session, chat_server_users_result_name(result));
    }

    chat_log(CHAT_LOG_INFO, "%s authenticated and online", session->username);
    return send_json(wsi, session, "{\"type\":\"auth_ok\"}");
}

static int handle_user_lookup(struct lws *wsi, chat_server_session_t *session, const char *json)
{
    if (!session->authenticated) {
        return send_error(wsi, session, "authentication_required");
    }

    char username[CHAT_USERNAME_MAX_LEN + 1u];
    if (!json_get_string(json, "username", username, sizeof(username))
        || !chat_username_is_valid(username)) {
        return send_error(wsi, session, "bad_lookup");
    }

    const chat_server_user_t *user = chat_server_users_find(&session->state->users, username);
    if (user == NULL) {
        char response[160];
        int written = snprintf(response,
                               sizeof(response),
                               "{\"type\":\"user_status\",\"username\":\"%s\",\"known\":false,\"online\":false}",
                               username);
        if (written < 0 || (size_t)written >= sizeof(response)) {
            return -1;
        }
        return send_json(wsi, session, response);
    }

    char public_key_hex[CHAT_SERVER_HEX_PUBLIC_KEY_LEN];
    (void)sodium_bin2hex(public_key_hex,
                         sizeof(public_key_hex),
                         user->identity_pk,
                         sizeof(user->identity_pk));

    char response[320];
    int written = snprintf(response,
                           sizeof(response),
                           "{\"type\":\"user_status\",\"username\":\"%s\",\"known\":true,\"online\":%s,"
                           "\"public_key\":\"%s\"}",
                           user->username,
                           user->online ? "true" : "false",
                           public_key_hex);
    if (written < 0 || (size_t)written >= sizeof(response)) {
        return -1;
    }

    return send_json(wsi, session, response);
}

static int handle_message(struct lws *wsi, chat_server_session_t *session, const char *json)
{
    char type[32];
    if (!json_get_string(json, "type", type, sizeof(type))) {
        return send_error(wsi, session, "missing_type");
    }

    if (strcmp(type, "register") == 0) {
        return handle_register(wsi, session, json);
    }
    if (strcmp(type, "hello") == 0) {
        return handle_hello(wsi, session, json);
    }
    if (strcmp(type, "auth_response") == 0) {
        return handle_auth_response(wsi, session, json);
    }
    if (strcmp(type, "user_lookup") == 0) {
        return handle_user_lookup(wsi, session, json);
    }

    return send_error(wsi, session, "unknown_type");
}

static int callback_chat_control(struct lws *wsi,
                                 enum lws_callback_reasons reason,
                                 void *user,
                                 void *in,
                                 size_t len)
{
    chat_server_session_t *session = user;

    switch (reason) {
    case LWS_CALLBACK_ESTABLISHED:
        memset(session, 0, sizeof(*session));
        session->state = lws_get_protocol(wsi)->user;
        chat_log(CHAT_LOG_DEBUG, "websocket established");
        return 0;

    case LWS_CALLBACK_RECEIVE: {
        if (len >= CHAT_SERVER_MAX_JSON_SIZE
            || lws_remaining_packet_payload(wsi) != 0
            || !lws_is_final_fragment(wsi)) {
            return send_error(wsi, session, "message_too_large_or_fragmented");
        }

        char json[CHAT_SERVER_MAX_JSON_SIZE];
        memcpy(json, in, len);
        json[len] = '\0';
        return handle_message(wsi, session, json);
    }

    case LWS_CALLBACK_SERVER_WRITEABLE:
        if (session->pending_len == 0u) {
            return 0;
        }

        if (lws_write(wsi,
                      &session->pending[LWS_PRE],
                      session->pending_len,
                      LWS_WRITE_TEXT) < (int)session->pending_len) {
            return -1;
        }
        session->pending_len = 0u;
        return 0;

    case LWS_CALLBACK_CLOSED:
        if (session != NULL && session->authenticated) {
            chat_log(CHAT_LOG_INFO, "%s disconnected", session->username);
            chat_server_users_set_offline_by_wsi(&session->state->users, wsi);
            sodium_memzero(session->challenge, sizeof(session->challenge));
        }
        return 0;

    default:
        return 0;
    }
}

static int parse_port(int argc, char **argv)
{
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            int port = atoi(argv[i + 1]);
            if (port > 0 && port <= 65535) {
                return port;
            }
        }
    }

    return CHAT_SERVER_DEFAULT_PORT;
}

int main(int argc, char **argv)
{
    if (sodium_init() < 0) {
        chat_log(CHAT_LOG_ERROR, "libsodium initialization failed");
        return 1;
    }

    chat_server_state_t state;
    chat_server_users_init(&state.users);

    struct lws_protocols protocols[] = {
        {
            .name = CHAT_SERVER_PROTOCOL_NAME,
            .callback = callback_chat_control,
            .per_session_data_size = sizeof(chat_server_session_t),
            .rx_buffer_size = CHAT_SERVER_MAX_JSON_SIZE,
            .id = 0,
            .user = &state,
            .tx_packet_size = CHAT_SERVER_MAX_JSON_SIZE,
        },
        {0}
    };

    struct lws_context_creation_info info;
    memset(&info, 0, sizeof(info));
    info.port = parse_port(argc, argv);
    info.protocols = protocols;
    info.options = LWS_SERVER_OPTION_HTTP_HEADERS_SECURITY_BEST_PRACTICES_ENFORCE;

    lws_set_log_level(LLL_ERR | LLL_WARN, NULL);

    struct lws_context *context = lws_create_context(&info);
    if (context == NULL) {
        chat_log(CHAT_LOG_ERROR, "failed to create libwebsockets context");
        return 1;
    }

    (void)signal(SIGINT, handle_signal);
    (void)signal(SIGTERM, handle_signal);

    chat_log(CHAT_LOG_INFO, "chat-server listening on ws://127.0.0.1:%d", info.port);
    while (!g_interrupted) {
        (void)lws_service(context, 50);
    }

    lws_context_destroy(context);
    return 0;
}
