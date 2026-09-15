#include "common/protocole.h"

#include <ctype.h>
#include <string.h>

static int chat_packet_type_is_valid(uint8_t type)
{
    return type >= CHAT_PKT_HANDSHAKE && type <= CHAT_PKT_PONG;
}

static void chat_write_u32_be(uint8_t out[4], uint32_t value)
{
    out[0] = (uint8_t)((value >> 24) & 0xffu);
    out[1] = (uint8_t)((value >> 16) & 0xffu);
    out[2] = (uint8_t)((value >> 8) & 0xffu);
    out[3] = (uint8_t)(value & 0xffu);
}

static uint32_t chat_read_u32_be(const uint8_t in[4])
{
    return ((uint32_t)in[0] << 24)
        | ((uint32_t)in[1] << 16)
        | ((uint32_t)in[2] << 8)
        | (uint32_t)in[3];
}

int chat_username_is_valid(const char *username)
{
    if (username == NULL) {
        return 0;
    }

    size_t len = strlen(username);
    if (len < CHAT_USERNAME_MIN_LEN || len > CHAT_USERNAME_MAX_LEN) {
        return 0;
    }

    for (size_t i = 0; i < len; ++i) {
        unsigned char ch = (unsigned char)username[i];
        if (!(isalnum(ch) || ch == '_' || ch == '-')) {
            return 0;
        }
    }

    return 1;
}

const char *chat_protocol_result_name(chat_protocol_result_t result)
{
    switch (result) {
    case CHAT_PROTOCOL_OK:
        return "ok";
    case CHAT_PROTOCOL_ERR_NULL:
        return "null pointer";
    case CHAT_PROTOCOL_ERR_SHORT_BUFFER:
        return "short buffer";
    case CHAT_PROTOCOL_ERR_BAD_VERSION:
        return "bad version";
    case CHAT_PROTOCOL_ERR_BAD_TYPE:
        return "bad packet type";
    case CHAT_PROTOCOL_ERR_TOO_LARGE:
        return "payload too large";
    case CHAT_PROTOCOL_ERR_TRUNCATED:
        return "truncated packet";
    }

    return "unknown protocol error";
}

chat_protocol_result_t chat_packet_encode_header(chat_packet_type_t type,
                                                 uint32_t payload_len,
                                                 uint8_t out[CHAT_PACKET_HEADER_SIZE])
{
    if (out == NULL) {
        return CHAT_PROTOCOL_ERR_NULL;
    }

    if (!chat_packet_type_is_valid((uint8_t)type)) {
        return CHAT_PROTOCOL_ERR_BAD_TYPE;
    }

    if (payload_len > CHAT_MAX_MESSAGE_SIZE) {
        return CHAT_PROTOCOL_ERR_TOO_LARGE;
    }

    out[0] = CHAT_PROTOCOL_VERSION;
    out[1] = (uint8_t)type;
    chat_write_u32_be(&out[2], payload_len);

    return CHAT_PROTOCOL_OK;
}

chat_protocol_result_t chat_packet_decode_header(const uint8_t *buffer,
                                                 size_t buffer_len,
                                                 chat_packet_header_t *out)
{
    if (buffer == NULL || out == NULL) {
        return CHAT_PROTOCOL_ERR_NULL;
    }

    if (buffer_len < CHAT_PACKET_HEADER_SIZE) {
        return CHAT_PROTOCOL_ERR_SHORT_BUFFER;
    }

    if (buffer[0] != CHAT_PROTOCOL_VERSION) {
        return CHAT_PROTOCOL_ERR_BAD_VERSION;
    }

    if (!chat_packet_type_is_valid(buffer[1])) {
        return CHAT_PROTOCOL_ERR_BAD_TYPE;
    }

    uint32_t length = chat_read_u32_be(&buffer[2]);
    if (length > CHAT_MAX_MESSAGE_SIZE) {
        return CHAT_PROTOCOL_ERR_TOO_LARGE;
    }

    if (buffer_len > CHAT_PACKET_HEADER_SIZE
        && buffer_len < CHAT_PACKET_HEADER_SIZE + (size_t)length) {
        return CHAT_PROTOCOL_ERR_TRUNCATED;
    }

    out->version = buffer[0];
    out->type = (chat_packet_type_t)buffer[1];
    out->length = length;

    return CHAT_PROTOCOL_OK;
}
