#define _POSIX_C_SOURCE 200809L

#include "common/identity.h"
#include "common/ipc.h"
#include "common/log.h"
#include "common/protocole.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

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
    const char command[] = "STATUS\n";
    char response[CHAT_IPC_MAX_RESPONSE];

    char socket_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
    if (chat_ipc_socket_path(socket_path, sizeof(socket_path)) != CHAT_IPC_OK) {
        fprintf(stderr, "Could not resolve chatd socket path.\n");
        return CHAT_EXIT_DAEMON_UNAVAILABLE;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        fprintf(stderr, "Could not create IPC socket: %s.\n", strerror(errno));
        return CHAT_EXIT_DAEMON_UNAVAILABLE;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    int copied = snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", socket_path);
    if (copied < 0 || (size_t)copied >= sizeof(addr.sun_path)) {
        fprintf(stderr, "chatd socket path is too long.\n");
        (void)close(fd);
        return CHAT_EXIT_DAEMON_UNAVAILABLE;
    }

    if (connect(fd, (const struct sockaddr *)&addr, sizeof(addr)) != 0) {
        fprintf(stderr, "chatd unavailable.\n");
        (void)close(fd);
        return CHAT_EXIT_DAEMON_UNAVAILABLE;
    }

    ssize_t written = write(fd, command, sizeof(command) - 1u);
    if (written != (ssize_t)(sizeof(command) - 1u)) {
        fprintf(stderr, "Could not write to chatd.\n");
        (void)close(fd);
        return CHAT_EXIT_DAEMON_UNAVAILABLE;
    }

    struct pollfd pfd = {.fd = fd, .events = POLLIN};
    int poll_result = poll(&pfd, 1u, 5000);
    if (poll_result <= 0) {
        fprintf(stderr, "chatd did not respond.\n");
        (void)close(fd);
        return CHAT_EXIT_DAEMON_UNAVAILABLE;
    }

    ssize_t bytes_read = read(fd, response, sizeof(response) - 1u);
    if (bytes_read <= 0) {
        fprintf(stderr, "Could not read from chatd.\n");
        (void)close(fd);
        return CHAT_EXIT_DAEMON_UNAVAILABLE;
    }

    response[bytes_read] = '\0';
    fputs(response, stdout);
    (void)close(fd);
    return CHAT_EXIT_SUCCESS;
}

static int ipc_request(const char *command, char *response, size_t response_size)
{
    char socket_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
    if (chat_ipc_socket_path(socket_path, sizeof(socket_path)) != CHAT_IPC_OK) {
        fprintf(stderr, "Could not resolve chatd socket path.\n");
        return -1;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        fprintf(stderr, "Could not create IPC socket: %s.\n", strerror(errno));
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    int copied = snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", socket_path);
    if (copied < 0 || (size_t)copied >= sizeof(addr.sun_path)) {
        fprintf(stderr, "chatd socket path is too long.\n");
        (void)close(fd);
        return -1;
    }

    if (connect(fd, (const struct sockaddr *)&addr, sizeof(addr)) != 0) {
        fprintf(stderr, "chatd unavailable.\n");
        (void)close(fd);
        return -1;
    }

    size_t command_len = strlen(command);
    ssize_t written = write(fd, command, command_len);
    if (written != (ssize_t)command_len) {
        fprintf(stderr, "Could not write to chatd.\n");
        (void)close(fd);
        return -1;
    }

    struct pollfd pfd = {.fd = fd, .events = POLLIN};
    int poll_result = poll(&pfd, 1u, 5000);
    if (poll_result <= 0) {
        fprintf(stderr, "chatd did not respond.\n");
        (void)close(fd);
        return -1;
    }

    ssize_t bytes_read = read(fd, response, response_size - 1u);
    if (bytes_read <= 0) {
        fprintf(stderr, "Could not read from chatd.\n");
        (void)close(fd);
        return -1;
    }

    response[bytes_read] = '\0';
    (void)close(fd);
    return 0;
}

static int command_open_chat(const char *peer)
{
    if (!chat_username_is_valid(peer)) {
        fprintf(stderr, "Invalid username. Use 3..32 characters: [a-zA-Z0-9_-].\n");
        return CHAT_EXIT_GENERIC_ERROR;
    }

    printf("Connecting to %s...\n", peer);

    char command[CHAT_IPC_MAX_COMMAND];
    int written = snprintf(command, sizeof(command), "OPEN_CHAT %s\n", peer);
    if (written < 0 || (size_t)written >= sizeof(command)) {
        return CHAT_EXIT_GENERIC_ERROR;
    }

    char response[CHAT_IPC_MAX_RESPONSE];
    if (ipc_request(command, response, sizeof(response)) != 0) {
        return CHAT_EXIT_DAEMON_UNAVAILABLE;
    }

    if (strncmp(response, "USER_OFFLINE ", 13u) == 0) {
        printf("%s is offline.\n", peer);
        return CHAT_EXIT_USER_OFFLINE;
    }

    if (strncmp(response, "USER_ONLINE ", 12u) == 0) {
        printf("%s is online, but the connection could not be established.\n", peer);
        return CHAT_EXIT_CONNECTION_FAILED;
    }

    if (strncmp(response, "ERROR ", 6u) == 0) {
        fprintf(stderr, "%s", response);
        return CHAT_EXIT_GENERIC_ERROR;
    }

    fprintf(stderr, "Unexpected response from chatd.\n");
    return CHAT_EXIT_GENERIC_ERROR;
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
