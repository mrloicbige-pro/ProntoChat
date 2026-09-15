#define _POSIX_C_SOURCE 200809L

#include "common/identity.h"
#include "common/ipc.h"
#include "common/log.h"

#include <errno.h>
#include <fcntl.h>
#include <libwebsockets.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
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

typedef enum {
    CHATD_PHASE_REGISTER,
    CHATD_PHASE_HELLO,
    CHATD_PHASE_AUTH_RESPONSE,
    CHATD_PHASE_ONLINE,
    CHATD_PHASE_FAILED
} chatd_phase_t;

typedef struct {
    chat_identity_t identity;
    chatd_phase_t phase;
    unsigned char challenge[CHATD_CHALLENGE_BYTES];
    int has_challenge;
    int connected;
    int should_reconnect;
    time_t next_reconnect_at;
    int ipc_fd;
    char ipc_socket_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
    unsigned char pending[LWS_PRE + CHATD_MAX_JSON_SIZE];
    size_t pending_len;
} chatd_state_t;

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

static int queue_json(struct lws *wsi, chatd_state_t *state, const char *json)
{
    size_t len = strlen(json);
    if (len >= CHATD_MAX_JSON_SIZE) {
        state->phase = CHATD_PHASE_FAILED;
        return -1;
    }

    memcpy(&state->pending[LWS_PRE], json, len);
    state->pending_len = len;
    (void)lws_callback_on_writable(wsi);
    return 0;
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
        if (state->pending_len == 0u) {
            return 0;
        }

        if (lws_write(wsi,
                      &state->pending[LWS_PRE],
                      state->pending_len,
                      LWS_WRITE_TEXT) < (int)state->pending_len) {
            state->phase = CHATD_PHASE_FAILED;
            return -1;
        }
        state->pending_len = 0u;
        return 0;

    case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
        chat_log(CHAT_LOG_WARN, "control server connection attempt reported an error");
        state->connected = 0;
        state->should_reconnect = 1;
        state->next_reconnect_at = time(NULL) + CHATD_RECONNECT_SECONDS;
        return 0;

    case LWS_CALLBACK_CLIENT_CLOSED:
        chat_log(CHAT_LOG_WARN, "control server connection closed");
        state->connected = 0;
        state->should_reconnect = 1;
        state->next_reconnect_at = time(NULL) + CHATD_RECONNECT_SECONDS;
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

static int set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }

    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
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

    if (set_nonblocking(fd) != 0) {
        chat_log(CHAT_LOG_ERROR, "failed to set IPC socket nonblocking");
        (void)close(fd);
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

    state->ipc_fd = fd;
    chat_log(CHAT_LOG_INFO, "IPC listening on %s", state->ipc_socket_path);
    return 0;
}

static void write_ipc_status(int client_fd, const chatd_state_t *state)
{
    const char *status = "OFFLINE";
    if (state->phase == CHATD_PHASE_ONLINE) {
        status = "ONLINE";
    } else if (state->connected) {
        status = "CONNECTING";
    }

    char response[CHAT_IPC_MAX_RESPONSE];
    int written = snprintf(response,
                           sizeof(response),
                           "%s %s\n",
                           status,
                           state->identity.username);
    if (written < 0 || (size_t)written >= sizeof(response)) {
        return;
    }

    (void)write(client_fd, response, (size_t)written);
}

static void handle_ipc_client(int client_fd, const chatd_state_t *state)
{
    char command[CHAT_IPC_MAX_COMMAND];
    ssize_t bytes_read = read(client_fd, command, sizeof(command) - 1u);
    if (bytes_read <= 0) {
        return;
    }

    command[bytes_read] = '\0';
    if (strcmp(command, "STATUS\n") == 0 || strcmp(command, "STATUS") == 0) {
        write_ipc_status(client_fd, state);
        return;
    }

    const char response[] = "ERROR unknown_command\n";
    (void)write(client_fd, response, sizeof(response) - 1u);
}

static void service_ipc(chatd_state_t *state)
{
    for (;;) {
        int client_fd = accept(state->ipc_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                chat_log(CHAT_LOG_WARN, "IPC accept failed: %s", strerror(errno));
            }
            return;
        }

        handle_ipc_client(client_fd, state);
        (void)close(client_fd);
    }
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
    chat_identity_result_t identity_result = chat_identity_load(&state.identity);
    if (identity_result != CHAT_IDENTITY_OK) {
        chat_log(CHAT_LOG_ERROR, "failed to load identity: %s",
                 chat_identity_result_name(identity_result));
        return 1;
    }

    char server_url[CHAT_IDENTITY_SERVER_URL_MAX];
    identity_result = chat_identity_load_server_url(server_url, sizeof(server_url));
    if (identity_result != CHAT_IDENTITY_OK) {
        chat_log(CHAT_LOG_ERROR, "failed to load server_url: %s",
                 chat_identity_result_name(identity_result));
        chat_identity_wipe(&state.identity);
        return 1;
    }

    char server_url_for_log[CHAT_IDENTITY_SERVER_URL_MAX];
    int copied = snprintf(server_url_for_log, sizeof(server_url_for_log), "%s", server_url);
    if (copied < 0 || (size_t)copied >= sizeof(server_url_for_log)) {
        chat_log(CHAT_LOG_ERROR, "server_url is too long");
        chat_identity_wipe(&state.identity);
        return 1;
    }

    const char *protocol = NULL;
    const char *address = NULL;
    const char *path = NULL;
    int port = 0;
    if (parse_server_url(server_url, &protocol, &address, &port, &path) != 0) {
        chat_log(CHAT_LOG_ERROR, "invalid server_url");
        chat_identity_wipe(&state.identity);
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
        return 1;
    }

    if (connect_control_server(context, protocol, address, port, path, &state) == NULL) {
        chat_log(CHAT_LOG_ERROR, "failed to start control server connection");
        lws_context_destroy(context);
        chat_identity_wipe(&state.identity);
        return 1;
    }

    if (start_ipc_server(&state) != 0) {
        lws_context_destroy(context);
        chat_identity_wipe(&state.identity);
        return 1;
    }

    (void)signal(SIGINT, handle_signal);
    (void)signal(SIGTERM, handle_signal);

    chat_log(CHAT_LOG_INFO, "chatd connecting to %s", server_url_for_log);
    while (!g_interrupted && state.phase != CHATD_PHASE_FAILED) {
        (void)lws_service(context, 50);
        service_ipc(&state);
        if (state.should_reconnect && !state.connected && time(NULL) >= state.next_reconnect_at) {
            chat_log(CHAT_LOG_INFO, "reconnecting to control server");
            if (connect_control_server(context, protocol, address, port, path, &state) == NULL) {
                state.next_reconnect_at = time(NULL) + CHATD_RECONNECT_SECONDS;
            }
        }
    }

    if (state.ipc_fd >= 0) {
        (void)close(state.ipc_fd);
        (void)unlink(state.ipc_socket_path);
    }
    lws_context_destroy(context);
    chat_identity_wipe(&state.identity);
    return state.phase == CHATD_PHASE_FAILED ? 1 : 0;
}
