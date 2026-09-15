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
    char content[128];
    int written = snprintf(content,
                           sizeof(content),
                           "username = \"%s\"\nserver_url = \"ws://127.0.0.1:8787\"\n",
                           username);
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

void chat_identity_wipe(chat_identity_t *identity)
{
    if (identity == NULL) {
        return;
    }

    sodium_memzero(identity->secret_key, sizeof(identity->secret_key));
}
