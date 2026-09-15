#include "common/identity.h"
#include "common/log.h"
#include "common/protocole.h"

#include <stdio.h>
#include <string.h>

static void print_usage(FILE *stream)
{
    fprintf(stream, "Usage:\n");
    fprintf(stream, "  chat init <username>\n");
    fprintf(stream, "  chat status\n");
    fprintf(stream, "  chat <username>\n");
}

static int command_init(const char *username)
{
    char fingerprint[CHAT_IDENTITY_FINGERPRINT_LEN];
    chat_identity_result_t result = chat_identity_create(username,
                                                         NULL,
                                                         fingerprint,
                                                         sizeof(fingerprint));

    if (result == CHAT_IDENTITY_ERR_INVALID_USERNAME) {
        fprintf(stderr, "Invalid username. Use 3..32 characters: [a-zA-Z0-9_-].\n");
        return CHAT_EXIT_GENERIC_ERROR;
    }

    if (result == CHAT_IDENTITY_ERR_ALREADY_EXISTS) {
        fprintf(stderr, "Identity already exists.\n");
        return CHAT_EXIT_GENERIC_ERROR;
    }

    if (result != CHAT_IDENTITY_OK) {
        fprintf(stderr, "Could not create identity: %s.\n", chat_identity_result_name(result));
        return CHAT_EXIT_GENERIC_ERROR;
    }

    printf("Created identity: %s\n", username);
    printf("Fingerprint: %s\n", fingerprint);
    return CHAT_EXIT_SUCCESS;
}

static int command_status(void)
{
    printf("chatd status is not implemented yet.\n");
    return CHAT_EXIT_DAEMON_UNAVAILABLE;
}

static int command_open_chat(const char *peer)
{
    if (!chat_username_is_valid(peer)) {
        fprintf(stderr, "Invalid username. Use 3..32 characters: [a-zA-Z0-9_-].\n");
        return CHAT_EXIT_GENERIC_ERROR;
    }

    printf("Connecting to %s...\n", peer);
    printf("%s is offline.\n", peer);
    return CHAT_EXIT_USER_OFFLINE;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        print_usage(stderr);
        return CHAT_EXIT_GENERIC_ERROR;
    }

    if (strcmp(argv[1], "init") == 0) {
        if (argc != 3) {
            print_usage(stderr);
            return CHAT_EXIT_GENERIC_ERROR;
        }
        return command_init(argv[2]);
    }

    if (strcmp(argv[1], "status") == 0) {
        if (argc != 2) {
            print_usage(stderr);
            return CHAT_EXIT_GENERIC_ERROR;
        }
        return command_status();
    }

    if (argc != 2) {
        print_usage(stderr);
        return CHAT_EXIT_GENERIC_ERROR;
    }

    return command_open_chat(argv[1]);
}
