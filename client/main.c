#define _POSIX_C_SOURCE 200809L

#include "common/contacts.h"
#include "common/identity.h"
#include "common/ipc.h"
#include "common/log.h"
#include "common/protocole.h"

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define CHAT_CLI_STATUS_TIMEOUT_MS 5000
#define CHAT_CLI_CHAT_TIMEOUT_MS 150000

static volatile sig_atomic_t g_chat_interrupted = 0;

static void handle_chat_signal(int signal_number)
{
    (void)signal_number;
    g_chat_interrupted = 1;
}

static void print_usage(FILE *stream)
{
    fprintf(stream, "Usage:\n");
    fprintf(stream, "  chat init <username>\n");
    fprintf(stream, "  chat status\n");
    fprintf(stream, "  chat fingerprint <username>\n");
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

static int command_fingerprint(const char *username)
{
    unsigned char identity_pk[crypto_sign_PUBLICKEYBYTES];
    chat_contacts_result_t result = chat_contacts_load_public_key(username, identity_pk);

    if (result == CHAT_CONTACTS_ERR_INVALID) {
        fprintf(stderr, "Invalid username. Use 3..32 characters: [a-zA-Z0-9_-].\n");
        return CHAT_EXIT_GENERIC_ERROR;
    }

    if (result == CHAT_CONTACTS_ERR_NOT_FOUND) {
        fprintf(stderr, "Unknown contact: %s.\n", username);
        return CHAT_EXIT_GENERIC_ERROR;
    }

    if (result != CHAT_CONTACTS_OK) {
        fprintf(stderr, "Could not read contact: %s.\n", chat_contacts_result_name(result));
        return CHAT_EXIT_GENERIC_ERROR;
    }

    char fingerprint[CHAT_IDENTITY_FINGERPRINT_LEN];
    chat_identity_result_t identity_result = chat_identity_fingerprint(identity_pk,
                                                                       fingerprint,
                                                                       sizeof(fingerprint));
    sodium_memzero(identity_pk, sizeof(identity_pk));
    if (identity_result != CHAT_IDENTITY_OK) {
        fprintf(stderr, "Could not compute fingerprint: %s.\n",
                chat_identity_result_name(identity_result));
        return CHAT_EXIT_GENERIC_ERROR;
    }

    printf("%s\n", username);
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
    int poll_result = poll(&pfd, 1u, CHAT_CLI_STATUS_TIMEOUT_MS);
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

static int open_ipc_socket(void)
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

    return fd;
}

static int write_all(int fd, const char *data, size_t data_len)
{
    size_t offset = 0u;
    while (offset < data_len) {
        ssize_t written = write(fd, &data[offset], data_len - offset);
        if (written <= 0) {
            return -1;
        }
        offset += (size_t)written;
    }

    return 0;
}

static int read_ipc_response(int fd, char *response, size_t response_size, int timeout_ms)
{
    struct pollfd pfd = {.fd = fd, .events = POLLIN};
    int poll_result = poll(&pfd, 1u, timeout_ms);
    if (poll_result <= 0) {
        return -1;
    }

    ssize_t bytes_read = read(fd, response, response_size - 1u);
    if (bytes_read <= 0) {
        return -1;
    }

    response[bytes_read] = '\0';
    return 0;
}

static int send_cli_chat_message(int fd, const char *line)
{
    char command[CHAT_IPC_MAX_COMMAND];
    int written = snprintf(command, sizeof(command), "SEND_MESSAGE %s\n", line);
    if (written < 0 || (size_t)written >= sizeof(command)) {
        fprintf(stderr, "Message too long.\n");
        return -1;
    }

    return write_all(fd, command, (size_t)written);
}

static const char *network_mode_label(const char *response)
{
    char status[32];
    char username[CHAT_USERNAME_MAX_LEN + 1u];
    char mode[16];
    if (sscanf(response, "%31s %32s %15s", status, username, mode) == 3
        && strcmp(mode, "relay") == 0) {
        return "TURN relay";
    }

    return "direct P2P";
}

static int run_chat_loop(int fd, const char *peer)
{
    char stdin_line[CHAT_IPC_MAX_COMMAND];
    char response[CHAT_IPC_MAX_RESPONSE];

    for (;;) {
        if (g_chat_interrupted) {
            (void)write_all(fd, "CLOSE_CHAT\n", sizeof("CLOSE_CHAT\n") - 1u);
            return CHAT_EXIT_SUCCESS;
        }

        struct pollfd pfds[2] = {
            {.fd = STDIN_FILENO, .events = POLLIN},
            {.fd = fd, .events = POLLIN}
        };

        int poll_result = poll(pfds, 2u, -1);
        if (poll_result < 0) {
            if (errno == EINTR && g_chat_interrupted) {
                (void)write_all(fd, "CLOSE_CHAT\n", sizeof("CLOSE_CHAT\n") - 1u);
                return CHAT_EXIT_SUCCESS;
            }
            if (errno == EINTR) {
                continue;
            }
            fprintf(stderr, "Chat interrupted: %s.\n", strerror(errno));
            return CHAT_EXIT_GENERIC_ERROR;
        }

        if ((pfds[1].revents & (POLLIN | POLLHUP)) != 0) {
            ssize_t bytes_read = read(fd, response, sizeof(response) - 1u);
            if (bytes_read <= 0) {
                printf("Chat closed.\n");
                return CHAT_EXIT_SUCCESS;
            }
            response[bytes_read] = '\0';

            if (strncmp(response, "MESSAGE ", 8u) == 0) {
                char *text = strchr(&response[8], ' ');
                if (text != NULL) {
                    *text++ = '\0';
                    text[strcspn(text, "\r\n")] = '\0';
                    printf("%-6s > %s\n", &response[8], text);
                }
                continue;
            }

            if (strncmp(response, "CHAT_CLOSED ", 12u) == 0) {
                printf("Chat closed by %s.\n", peer);
                return CHAT_EXIT_SUCCESS;
            }

            if (strncmp(response, "ERROR ", 6u) == 0) {
                fprintf(stderr, "%s", response);
                return CHAT_EXIT_GENERIC_ERROR;
            }
        }

        if ((pfds[0].revents & (POLLIN | POLLHUP)) != 0) {
            if (fgets(stdin_line, sizeof(stdin_line), stdin) == NULL) {
                (void)write_all(fd, "CLOSE_CHAT\n", sizeof("CLOSE_CHAT\n") - 1u);
                return CHAT_EXIT_SUCCESS;
            }

            size_t line_len = strcspn(stdin_line, "\r\n");
            stdin_line[line_len] = '\0';
            if (line_len == 0u) {
                continue;
            }

            if (send_cli_chat_message(fd, stdin_line) != 0) {
                fprintf(stderr, "Could not send message.\n");
                return CHAT_EXIT_GENERIC_ERROR;
            }
            printf("you    > %s\n", stdin_line);
        }
    }
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

    int fd = open_ipc_socket();
    if (fd < 0) {
        return CHAT_EXIT_DAEMON_UNAVAILABLE;
    }

    if (write_all(fd, command, strlen(command)) != 0) {
        fprintf(stderr, "Could not write to chatd.\n");
        (void)close(fd);
        return CHAT_EXIT_DAEMON_UNAVAILABLE;
    }

    char response[CHAT_IPC_MAX_RESPONSE];
    if (read_ipc_response(fd, response, sizeof(response), CHAT_CLI_CHAT_TIMEOUT_MS) != 0) {
        fprintf(stderr, "chatd did not respond.\n");
        (void)close(fd);
        return CHAT_EXIT_DAEMON_UNAVAILABLE;
    }

    if (strncmp(response, "USER_OFFLINE ", 13u) == 0) {
        (void)close(fd);
        printf("%s is offline.\n", peer);
        return CHAT_EXIT_USER_OFFLINE;
    }

    if (strncmp(response, "USER_ONLINE ", 12u) == 0) {
        (void)close(fd);
        printf("%s is online, but the connection could not be established.\n", peer);
        return CHAT_EXIT_CONNECTION_FAILED;
    }

    if (strncmp(response, "ENCRYPTED_SESSION ", 18u) == 0) {
        printf("Connected to %s [%s]\n", peer, network_mode_label(response));
        printf("Encrypted session established.\n");
        g_chat_interrupted = 0;
        void (*previous_handler)(int) = signal(SIGINT, handle_chat_signal);
        int result = run_chat_loop(fd, peer);
        if (previous_handler != SIG_ERR) {
            (void)signal(SIGINT, previous_handler);
        }
        (void)close(fd);
        return result;
    }

    if (strncmp(response, "ICE_CONNECTED ", 14u) == 0) {
        (void)close(fd);
        printf("Connected to %s [direct P2P]\n", peer);
        printf("Encrypted session is not fully established.\n");
        return CHAT_EXIT_CONNECTION_FAILED;
    }

    if (strncmp(response, "ICE_FAILED ", 11u) == 0) {
        (void)close(fd);
        printf("%s is online, but the connection could not be established.\n", peer);
        return CHAT_EXIT_CONNECTION_FAILED;
    }

    if (strncmp(response, "IDENTITY_MISMATCH ", 18u) == 0) {
        (void)close(fd);
        fprintf(stderr, "SECURITY ERROR:\n");
        fprintf(stderr, "%s's identity key changed.\n", peer);
        fprintf(stderr, "Connection refused.\n");
        return CHAT_EXIT_IDENTITY_MISMATCH;
    }

    if (strncmp(response, "ERROR ", 6u) == 0) {
        (void)close(fd);
        fprintf(stderr, "%s", response);
        return CHAT_EXIT_GENERIC_ERROR;
    }

    (void)close(fd);
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

    if (strcmp(argv[1], "fingerprint") == 0) {
        if (argc != 3) {
            print_usage(stderr);
            return CHAT_EXIT_GENERIC_ERROR;
        }
        return command_fingerprint(argv[2]);
    }

    if (argc != 2) {
        print_usage(stderr);
        return CHAT_EXIT_GENERIC_ERROR;
    }

    return command_open_chat(argv[1]);
}
