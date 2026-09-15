#include "common/protocole.h"

#include <assert.h>
#include <stdint.h>

static void test_username_validation(void)
{
    assert(chat_username_is_valid("alex"));
    assert(chat_username_is_valid("nathan_42"));
    assert(!chat_username_is_valid("ab"));
    assert(!chat_username_is_valid("name with spaces"));
    assert(!chat_username_is_valid(NULL));
}

static void test_packet_header_roundtrip(void)
{
    uint8_t buffer[CHAT_PACKET_HEADER_SIZE] = {0};
    chat_packet_header_t header = {0};

    assert(chat_packet_encode_header(CHAT_PKT_MESSAGE, 42u, buffer) == CHAT_PROTOCOL_OK);
    assert(chat_packet_decode_header(buffer, sizeof(buffer), &header) == CHAT_PROTOCOL_OK);
    assert(header.version == CHAT_PROTOCOL_VERSION);
    assert(header.type == CHAT_PKT_MESSAGE);
    assert(header.length == 42u);
}

static void test_packet_rejects_bad_inputs(void)
{
    uint8_t buffer[CHAT_PACKET_HEADER_SIZE] = {0};
    chat_packet_header_t header = {0};

    assert(chat_packet_encode_header((chat_packet_type_t)99u, 0u, buffer) == CHAT_PROTOCOL_ERR_BAD_TYPE);
    assert(chat_packet_encode_header(CHAT_PKT_MESSAGE, CHAT_MAX_MESSAGE_SIZE + 1u, buffer)
        == CHAT_PROTOCOL_ERR_TOO_LARGE);

    assert(chat_packet_encode_header(CHAT_PKT_MESSAGE, 12u, buffer) == CHAT_PROTOCOL_OK);
    buffer[0] = 99u;
    assert(chat_packet_decode_header(buffer, sizeof(buffer), &header) == CHAT_PROTOCOL_ERR_BAD_VERSION);

    buffer[0] = CHAT_PROTOCOL_VERSION;
    buffer[1] = 99u;
    assert(chat_packet_decode_header(buffer, sizeof(buffer), &header) == CHAT_PROTOCOL_ERR_BAD_TYPE);

    assert(chat_packet_decode_header(buffer, CHAT_PACKET_HEADER_SIZE - 1u, &header)
        == CHAT_PROTOCOL_ERR_SHORT_BUFFER);
}

int main(void)
{
    test_username_validation();
    test_packet_header_roundtrip();
    test_packet_rejects_bad_inputs();
    return 0;
}
