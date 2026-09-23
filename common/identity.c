#define _POSIX_C_SOURCE 200809L

#include "common/identity.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define CHAT_IDENTITY_KEY_FILE "identity.key"
#define CHAT_IDENTITY_PUB_FILE "identity.pub"
#define CHAT_CONFIG_FILE "config.toml"

static chat_identity_result_t chat_copy_string(char *out, size_t out_size, const char *value)
{
    if (out == NULL || value == NULL || out_size == 0u) {
        return CHAT_IDENTITY_ERR_BUFFER;
    }

    int written = snprintf(out, out_size, "%s", value);
    if (written < 0 || (size_t)written >= out_size) {
        return CHAT_IDENTITY_ERR_BUFFER;
    }

    return CHAT_IDENTITY_OK;
}

static chat_identity_result_t chat_join_path(char *out,
                                             size_t out_size,
                                             const char *dir,
                                             const char *file)
{
    if (out == NULL || dir == NULL || file == NULL || out_size == 0u) {
        return CHAT_IDENTITY_ERR_BUFFER;
    }

    int written = snprintf(out, out_size, "%s/%s", dir, file);
    if (written < 0 || (size_t)written >= out_size) {
        return CHAT_IDENTITY_ERR_BUFFER;
    }

    return CHAT_IDENTITY_OK;
}

static chat_identity_result_t chat_mkdir_one(const char *path, mode_t mode)
{
    if (mkdir(path, mode) == 0) {
        return CHAT_IDENTITY_OK;
    }

    if (errno == EEXIST) {
        struct stat st;
        if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
            return CHAT_IDENTITY_OK;
        }
    }

    return CHAT_IDENTITY_ERR_IO;
}

static chat_identity_result_t chat_mkdir_p(const char *path, mode_t mode)
{
    if (path == NULL || path[0] == '\0') {
        return CHAT_IDENTITY_ERR_IO;
    }

    char tmp[PATH_MAX];
    chat_identity_result_t copy_result = chat_copy_string(tmp, sizeof(tmp), path);
    if (copy_result != CHAT_IDENTITY_OK) {
        return copy_result;
    }

    size_t len = strlen(tmp);
    if (len > 1u && tmp[len - 1u] == '/') {
        tmp[len - 1u] = '\0';
    }

    for (char *cursor = tmp + 1; *cursor != '\0'; ++cursor) {
        if (*cursor != '/') {
            continue;
        }

        *cursor = '\0';
        chat_identity_result_t result = chat_mkdir_one(tmp, mode);
        *cursor = '/';
        if (result != CHAT_IDENTITY_OK) {
            return result;
        }
    }

    return chat_mkdir_one(tmp, mode);
}

static chat_identity_result_t chat_write_all(int fd, const void *buffer, size_t length)
{
    const unsigned char *cursor = buffer;
    size_t remaining = length;

    while (remaining > 0u) {
        ssize_t written = write(fd, cursor, remaining);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return CHAT_IDENTITY_ERR_IO;
        }

        if (written == 0) {
            return CHAT_IDENTITY_ERR_IO;
        }

        cursor += (size_t)written;
        remaining -= (size_t)written;
    }

    return CHAT_IDENTITY_OK;
}

static chat_identity_result_t chat_read_exact_file(const char *path, void *buffer, size_t length)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return errno == ENOENT ? CHAT_IDENTITY_ERR_NOT_FOUND : CHAT_IDENTITY_ERR_IO;
    }

    unsigned char *cursor = buffer;
    size_t remaining = length;
    while (remaining > 0u) {
        ssize_t bytes_read = read(fd, cursor, remaining);
        if (bytes_read < 0) {
            if (errno == EINTR) {
                continue;
            }
            (void)close(fd);
            return CHAT_IDENTITY_ERR_IO;
        }

        if (bytes_read == 0) {
            (void)close(fd);
            return CHAT_IDENTITY_ERR_BAD_FILE;
        }

        cursor += (size_t)bytes_read;
        remaining -= (size_t)bytes_read;
    }

    unsigned char extra = 0u;
    ssize_t extra_read = read(fd, &extra, 1u);
    (void)close(fd);
    if (extra_read < 0) {
        return CHAT_IDENTITY_ERR_IO;
    }
    if (extra_read != 0) {
        return CHAT_IDENTITY_ERR_BAD_FILE;
    }

    return CHAT_IDENTITY_OK;
}

static chat_identity_result_t chat_write_new_file(const char *path,
                                                  const void *buffer,
                                                  size_t length,
                                                  mode_t mode)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, mode);
    if (fd < 0) {
        return errno == EEXIST ? CHAT_IDENTITY_ERR_ALREADY_EXISTS : CHAT_IDENTITY_ERR_IO;
    }

    chat_identity_result_t result = chat_write_all(fd, buffer, length);
    if (fsync(fd) != 0 && result == CHAT_IDENTITY_OK) {
        result = CHAT_IDENTITY_ERR_IO;
    }

    if (close(fd) != 0 && result == CHAT_IDENTITY_OK) {
        result = CHAT_IDENTITY_ERR_IO;
    }

    return result;
}

static chat_identity_result_t chat_write_config_file(const char *path, const char *username)
{
    char content[512];
    int written = snprintf(content,
                           sizeof(content),
                           "username = \"%s\"\nserver_url = \"%s\"\n",
                           username,
                           CHAT_DEFAULT_SERVER_URL);
    if (written < 0 || (size_t)written >= sizeof(content)) {
        return CHAT_IDENTITY_ERR_BUFFER;
    }

    return chat_write_new_file(path, content, (size_t)written, 0600);
}

static chat_identity_result_t chat_load_username(const char *path,
                                                 char username[CHAT_USERNAME_MAX_LEN + 1u])
{
    FILE *file = fopen(path, "r");
    if (file == NULL) {
        return errno == ENOENT ? CHAT_IDENTITY_ERR_NOT_FOUND : CHAT_IDENTITY_ERR_IO;
    }

    char line[128];
    while (fgets(line, sizeof(line), file) != NULL) {
        char parsed[CHAT_USERNAME_MAX_LEN + 1u];
        if (sscanf(line, "username = \"%32[a-zA-Z0-9_-]\"", parsed) == 1) {
            (void)fclose(file);
            if (!chat_username_is_valid(parsed)) {
                return CHAT_IDENTITY_ERR_BAD_FILE;
            }
            (void)snprintf(username, CHAT_USERNAME_MAX_LEN + 1u, "%s", parsed);
            return CHAT_IDENTITY_OK;
        }
    }

    if (ferror(file)) {
        (void)fclose(file);
        return CHAT_IDENTITY_ERR_IO;
    }

    (void)fclose(file);
    return CHAT_IDENTITY_ERR_BAD_FILE;
}

static chat_identity_result_t chat_load_quoted_config_value(const char *path,
                                                            const char *key,
                                                            char *out,
                                                            size_t out_size)
{
    FILE *file = fopen(path, "r");
    if (file == NULL) {
        return errno == ENOENT ? CHAT_IDENTITY_ERR_NOT_FOUND : CHAT_IDENTITY_ERR_IO;
    }

    char prefix[64];
    int prefix_len = snprintf(prefix, sizeof(prefix), "%s = \"", key);
    if (prefix_len < 0 || (size_t)prefix_len >= sizeof(prefix)) {
        (void)fclose(file);
        return CHAT_IDENTITY_ERR_BUFFER;
    }

    char line[512];
    while (fgets(line, sizeof(line), file) != NULL) {
        if (strncmp(line, prefix, (size_t)prefix_len) != 0) {
            continue;
        }

        char *value_start = &line[prefix_len];
        char *value_end = strchr(value_start, '"');
        if (value_end == NULL) {
            (void)fclose(file);
            return CHAT_IDENTITY_ERR_BAD_FILE;
        }
        *value_end = '\0';
        chat_identity_result_t result = chat_copy_string(out, out_size, value_start);
        (void)fclose(file);
        return result;
    }

    if (ferror(file)) {
        (void)fclose(file);
        return CHAT_IDENTITY_ERR_IO;
    }

    (void)fclose(file);
    return CHAT_IDENTITY_ERR_NOT_FOUND;
}

static int chat_config_line_has_key(const char *line, const char *key)
{
    while (*line == ' ' || *line == '\t') {
        ++line;
    }

    size_t key_length = strlen(key);
    if (strncmp(line, key, key_length) != 0) {
        return 0;
    }

    line += key_length;
    while (*line == ' ' || *line == '\t') {
        ++line;
    }
    return *line == '=';
}

static int chat_server_url_is_valid(const char *server_url)
{
    if (server_url == NULL) {
        return 0;
    }

    size_t length = strlen(server_url);
    if (length == 0u || length >= CHAT_IDENTITY_SERVER_URL_MAX) {
        return 0;
    }

    const char *authority = NULL;
    if (strncmp(server_url, "ws://", 5u) == 0) {
        authority = server_url + 5u;
    } else if (strncmp(server_url, "wss://", 6u) == 0) {
        authority = server_url + 6u;
    } else {
        return 0;
    }

    if (*authority == '\0' || *authority == '/' || *authority == '?' || *authority == '#') {
        return 0;
    }

    for (const unsigned char *cursor = (const unsigned char *)server_url;
         *cursor != '\0';
         ++cursor) {
        if (*cursor <= 0x20u || *cursor == 0x7fu || *cursor == '"' || *cursor == '\\') {
            return 0;
        }
    }

    return 1;
}

const char *chat_identity_result_name(chat_identity_result_t result)
{
    switch (result) {
    case CHAT_IDENTITY_OK:
        return "ok";
    case CHAT_IDENTITY_ERR_INVALID_USERNAME:
        return "invalid username";
    case CHAT_IDENTITY_ERR_ALREADY_EXISTS:
        return "identity already exists";
    case CHAT_IDENTITY_ERR_SODIUM:
        return "libsodium failure";
    case CHAT_IDENTITY_ERR_IO:
        return "I/O error";
    case CHAT_IDENTITY_ERR_BUFFER:
        return "buffer too small";
    case CHAT_IDENTITY_ERR_NOT_FOUND:
        return "identity not found";
    case CHAT_IDENTITY_ERR_BAD_FILE:
        return "invalid identity file";
    case CHAT_IDENTITY_ERR_INVALID_SERVER_URL:
        return "invalid server URL";
    }

    return "unknown identity error";
}

chat_identity_result_t chat_identity_config_dir(char *out, size_t out_size)
{
    const char *override = getenv(CHAT_CONFIG_DIR_ENV);
    if (override != NULL && override[0] != '\0') {
        return chat_copy_string(out, out_size, override);
    }

#ifdef __APPLE__
    const char *home = getenv("HOME");
    if (home == NULL || home[0] == '\0') {
        return CHAT_IDENTITY_ERR_IO;
    }
    int written = snprintf(out, out_size, "%s/Library/Application Support/chat", home);
#else
    const char *xdg_config_home = getenv("XDG_CONFIG_HOME");
    if (xdg_config_home != NULL && xdg_config_home[0] != '\0') {
        int written = snprintf(out, out_size, "%s/chat", xdg_config_home);
        if (written < 0 || (size_t)written >= out_size) {
            return CHAT_IDENTITY_ERR_BUFFER;
        }
        return CHAT_IDENTITY_OK;
    }

    const char *home = getenv("HOME");
    if (home == NULL || home[0] == '\0') {
        return CHAT_IDENTITY_ERR_IO;
    }
    int written = snprintf(out, out_size, "%s/.config/chat", home);
#endif

    if (written < 0 || (size_t)written >= out_size) {
        return CHAT_IDENTITY_ERR_BUFFER;
    }

    return CHAT_IDENTITY_OK;
}

chat_identity_result_t chat_identity_fingerprint(
    const unsigned char public_key[crypto_sign_PUBLICKEYBYTES],
    char *out,
    size_t out_size)
{
    if (public_key == NULL || out == NULL) {
        return CHAT_IDENTITY_ERR_BUFFER;
    }

    unsigned char digest[crypto_generichash_BYTES];
    if (crypto_generichash(digest, sizeof(digest), public_key, crypto_sign_PUBLICKEYBYTES, NULL, 0u) != 0) {
        return CHAT_IDENTITY_ERR_SODIUM;
    }

    size_t required = (sizeof(digest) * 3u);
    if (out_size < required) {
        sodium_memzero(digest, sizeof(digest));
        return CHAT_IDENTITY_ERR_BUFFER;
    }

    size_t offset = 0u;
    for (size_t i = 0u; i < sizeof(digest); ++i) {
        int written = snprintf(&out[offset], out_size - offset, i == 0u ? "%02X" : ":%02X", digest[i]);
        if (written < 0 || (size_t)written >= out_size - offset) {
            sodium_memzero(digest, sizeof(digest));
            return CHAT_IDENTITY_ERR_BUFFER;
        }
        offset += (size_t)written;
    }

    sodium_memzero(digest, sizeof(digest));
    return CHAT_IDENTITY_OK;
}

chat_identity_result_t chat_identity_create(const char *username,
                                            chat_identity_t *out_identity,
                                            char *fingerprint_out,
                                            size_t fingerprint_out_size)
{
    if (!chat_username_is_valid(username)) {
        return CHAT_IDENTITY_ERR_INVALID_USERNAME;
    }

    if (sodium_init() < 0) {
        return CHAT_IDENTITY_ERR_SODIUM;
    }

    char config_dir[PATH_MAX];
    chat_identity_result_t result = chat_identity_config_dir(config_dir, sizeof(config_dir));
    if (result != CHAT_IDENTITY_OK) {
        return result;
    }

    result = chat_mkdir_p(config_dir, 0700);
    if (result != CHAT_IDENTITY_OK) {
        return result;
    }

    char key_path[PATH_MAX];
    char pub_path[PATH_MAX];
    char config_path[PATH_MAX];
    result = chat_join_path(key_path, sizeof(key_path), config_dir, CHAT_IDENTITY_KEY_FILE);
    if (result != CHAT_IDENTITY_OK) {
        return result;
    }
    result = chat_join_path(pub_path, sizeof(pub_path), config_dir, CHAT_IDENTITY_PUB_FILE);
    if (result != CHAT_IDENTITY_OK) {
        return result;
    }
    result = chat_join_path(config_path, sizeof(config_path), config_dir, CHAT_CONFIG_FILE);
    if (result != CHAT_IDENTITY_OK) {
        return result;
    }

    if (access(key_path, F_OK) == 0 || access(pub_path, F_OK) == 0 || access(config_path, F_OK) == 0) {
        return CHAT_IDENTITY_ERR_ALREADY_EXISTS;
    }

    chat_identity_t identity;
    memset(&identity, 0, sizeof(identity));
    (void)snprintf(identity.username, sizeof(identity.username), "%s", username);
    crypto_sign_keypair(identity.public_key, identity.secret_key);

    result = chat_write_new_file(key_path,
                                 identity.secret_key,
                                 sizeof(identity.secret_key),
                                 0600);
    if (result != CHAT_IDENTITY_OK) {
        chat_identity_wipe(&identity);
        return result;
    }

    result = chat_write_new_file(pub_path,
                                 identity.public_key,
                                 sizeof(identity.public_key),
                                 0644);
    if (result != CHAT_IDENTITY_OK) {
        chat_identity_wipe(&identity);
        return result;
    }

    result = chat_write_config_file(config_path, username);
    if (result != CHAT_IDENTITY_OK) {
        chat_identity_wipe(&identity);
        return result;
    }

    if (fingerprint_out != NULL) {
        result = chat_identity_fingerprint(identity.public_key, fingerprint_out, fingerprint_out_size);
        if (result != CHAT_IDENTITY_OK) {
            chat_identity_wipe(&identity);
            return result;
        }
    }

    if (out_identity != NULL) {
        *out_identity = identity;
    }

    chat_identity_wipe(&identity);
    return CHAT_IDENTITY_OK;
}

chat_identity_result_t chat_identity_load(chat_identity_t *out_identity)
{
    if (out_identity == NULL) {
        return CHAT_IDENTITY_ERR_BUFFER;
    }

    if (sodium_init() < 0) {
        return CHAT_IDENTITY_ERR_SODIUM;
    }

    char config_dir[PATH_MAX];
    chat_identity_result_t result = chat_identity_config_dir(config_dir, sizeof(config_dir));
    if (result != CHAT_IDENTITY_OK) {
        return result;
    }

    char key_path[PATH_MAX];
    char pub_path[PATH_MAX];
    char config_path[PATH_MAX];
    result = chat_join_path(key_path, sizeof(key_path), config_dir, CHAT_IDENTITY_KEY_FILE);
    if (result != CHAT_IDENTITY_OK) {
        return result;
    }
    result = chat_join_path(pub_path, sizeof(pub_path), config_dir, CHAT_IDENTITY_PUB_FILE);
    if (result != CHAT_IDENTITY_OK) {
        return result;
    }
    result = chat_join_path(config_path, sizeof(config_path), config_dir, CHAT_CONFIG_FILE);
    if (result != CHAT_IDENTITY_OK) {
        return result;
    }

    chat_identity_t identity;
    memset(&identity, 0, sizeof(identity));
    result = chat_load_username(config_path, identity.username);
    if (result != CHAT_IDENTITY_OK) {
        return result;
    }

    result = chat_read_exact_file(key_path, identity.secret_key, sizeof(identity.secret_key));
    if (result != CHAT_IDENTITY_OK) {
        chat_identity_wipe(&identity);
        return result;
    }

    result = chat_read_exact_file(pub_path, identity.public_key, sizeof(identity.public_key));
    if (result != CHAT_IDENTITY_OK) {
        chat_identity_wipe(&identity);
        return result;
    }

    *out_identity = identity;
    chat_identity_wipe(&identity);
    return CHAT_IDENTITY_OK;
}

chat_identity_result_t chat_identity_load_server_url(char *out, size_t out_size)
{
    return chat_identity_load_config_value("server_url", out, out_size);
}

chat_identity_result_t chat_identity_set_server_url(const char *server_url)
{
    if (!chat_server_url_is_valid(server_url)) {
        return CHAT_IDENTITY_ERR_INVALID_SERVER_URL;
    }

    char config_dir[PATH_MAX];
    chat_identity_result_t result = chat_identity_config_dir(config_dir, sizeof(config_dir));
    if (result != CHAT_IDENTITY_OK) {
        return result;
    }

    char config_path[PATH_MAX];
    result = chat_join_path(config_path, sizeof(config_path), config_dir, CHAT_CONFIG_FILE);
    if (result != CHAT_IDENTITY_OK) {
        return result;
    }

    FILE *input = fopen(config_path, "r");
    if (input == NULL) {
        return errno == ENOENT ? CHAT_IDENTITY_ERR_NOT_FOUND : CHAT_IDENTITY_ERR_IO;
    }

    char temp_path[PATH_MAX];
    int path_length = snprintf(temp_path, sizeof(temp_path), "%s.tmp.XXXXXX", config_path);
    if (path_length < 0 || (size_t)path_length >= sizeof(temp_path)) {
        (void)fclose(input);
        return CHAT_IDENTITY_ERR_BUFFER;
    }

    int temp_fd = mkstemp(temp_path);
    if (temp_fd < 0) {
        (void)fclose(input);
        return CHAT_IDENTITY_ERR_IO;
    }
    if (fchmod(temp_fd, 0600) != 0) {
        (void)close(temp_fd);
        (void)unlink(temp_path);
        (void)fclose(input);
        return CHAT_IDENTITY_ERR_IO;
    }

    FILE *output = fdopen(temp_fd, "w");
    if (output == NULL) {
        (void)close(temp_fd);
        (void)unlink(temp_path);
        (void)fclose(input);
        return CHAT_IDENTITY_ERR_IO;
    }

    char *line = NULL;
    size_t capacity = 0u;
    int server_url_written = 0;
    int had_content = 0;
    int last_line_had_newline = 1;
    result = CHAT_IDENTITY_OK;

    while (getline(&line, &capacity, input) >= 0) {
        had_content = 1;
        last_line_had_newline = line[0] != '\0' && line[strlen(line) - 1u] == '\n';

        if (chat_config_line_has_key(line, "server_url")) {
            if (!server_url_written
                && fprintf(output, "server_url = \"%s\"\n", server_url) < 0) {
                result = CHAT_IDENTITY_ERR_IO;
                break;
            }
            server_url_written = 1;
            continue;
        }

        if (fputs(line, output) == EOF) {
            result = CHAT_IDENTITY_ERR_IO;
            break;
        }
    }

    if (result == CHAT_IDENTITY_OK && ferror(input)) {
        result = CHAT_IDENTITY_ERR_IO;
    }

    if (result == CHAT_IDENTITY_OK && !server_url_written) {
        if (had_content && !last_line_had_newline && fputc('\n', output) == EOF) {
            result = CHAT_IDENTITY_ERR_IO;
        } else if (fprintf(output, "server_url = \"%s\"\n", server_url) < 0) {
            result = CHAT_IDENTITY_ERR_IO;
        }
    }

    free(line);
    if (fclose(input) != 0 && result == CHAT_IDENTITY_OK) {
        result = CHAT_IDENTITY_ERR_IO;
    }
    if (fflush(output) != 0 && result == CHAT_IDENTITY_OK) {
        result = CHAT_IDENTITY_ERR_IO;
    }
    if (fsync(fileno(output)) != 0 && result == CHAT_IDENTITY_OK) {
        result = CHAT_IDENTITY_ERR_IO;
    }
    if (fclose(output) != 0 && result == CHAT_IDENTITY_OK) {
        result = CHAT_IDENTITY_ERR_IO;
    }

    if (result == CHAT_IDENTITY_OK && rename(temp_path, config_path) != 0) {
        result = CHAT_IDENTITY_ERR_IO;
    }
    if (result != CHAT_IDENTITY_OK) {
        (void)unlink(temp_path);
    }

    return result;
}

chat_identity_result_t chat_identity_load_config_value(const char *key,
                                                       char *out,
                                                       size_t out_size)
{
    char config_dir[PATH_MAX];
    chat_identity_result_t result = chat_identity_config_dir(config_dir, sizeof(config_dir));
    if (result != CHAT_IDENTITY_OK) {
        return result;
    }

    char config_path[PATH_MAX];
    result = chat_join_path(config_path, sizeof(config_path), config_dir, CHAT_CONFIG_FILE);
    if (result != CHAT_IDENTITY_OK) {
        return result;
    }

    return chat_load_quoted_config_value(config_path, key, out, out_size);
}

void chat_identity_wipe(chat_identity_t *identity)
{
    if (identity == NULL) {
        return;
    }

    sodium_memzero(identity->secret_key, sizeof(identity->secret_key));
}
