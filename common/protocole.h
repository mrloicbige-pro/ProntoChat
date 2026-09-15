#ifndef CHAT_PROTOCOLE_H
#define CHAT_PROTOCOLE_H

#include <stddef.h>
#include <stdint.h>

#define CHAT_PROTOCOL_VERSION 1u
#define CHAT_PACKET_HEADER_SIZE 6u
#define CHAT_MAX_MESSAGE_SIZE (64u * 1024u)
#define CHAT_USERNAME_MIN_LEN 3u
#define CHAT_USERNAME_MAX_LEN 32u

typedef enum {
    CHAT_EXIT_SUCCESS = 0,
    CHAT_EXIT_GENERIC_ERROR = 1,
    CHAT_EXIT_USER_OFFLINE = 2,
    CHAT_EXIT_CONNECTION_FAILED = 3,
    CHAT_EXIT_IDENTITY_MISMATCH = 4,
    CHAT_EXIT_DAEMON_UNAVAILABLE = 5,
    CHAT_EXIT_AUTHENTICATION_FAILED = 6
} chat_exit_code_t;

typedef enum {
    CHAT_PKT_HANDSHAKE = 1,
    CHAT_PKT_STREAM_HEADER = 2,
    CHAT_PKT_MESSAGE = 3,
    CHAT_PKT_CLOSE = 4,
    CHAT_PKT_PING = 5,
    CHAT_PKT_PONG = 6
} chat_packet_type_t;

typedef enum {
    CHAT_PROTOCOL_OK = 0,
    CHAT_PROTOCOL_ERR_NULL = -1,
    CHAT_PROTOCOL_ERR_SHORT_BUFFER = -2,
    CHAT_PROTOCOL_ERR_BAD_VERSION = -3,
    CHAT_PROTOCOL_ERR_BAD_TYPE = -4,
    CHAT_PROTOCOL_ERR_TOO_LARGE = -5,
    CHAT_PROTOCOL_ERR_TRUNCATED = -6
} chat_protocol_result_t;

typedef struct {
    uint8_t version;
    chat_packet_type_t type;
    uint32_t length;
} chat_packet_header_t;

int chat_username_is_valid(const char *username);
const char *chat_protocol_result_name(chat_protocol_result_t result);

chat_protocol_result_t chat_packet_encode_header(chat_packet_type_t type,
                                                 uint32_t payload_len,
                                                 uint8_t out[CHAT_PACKET_HEADER_SIZE]);

chat_protocol_result_t chat_packet_decode_header(const uint8_t *buffer,
                                                 size_t buffer_len,
                                                 chat_packet_header_t *out);

#endif
