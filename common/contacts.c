#define _POSIX_C_SOURCE 200809L

#include "common/contacts.h"

#include "common/identity.h"
#include "common/protocole.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define CHAT_CONTACTS_FILE "contacts.db"
#define CHAT_CONTACTS_HEX_PUBLIC_KEY_LEN (crypto_sign_PUBLICKEYBYTES * 2u + 1u)
#define CHAT_CONTACTS_LINE_MAX \
    (CHAT_USERNAME_MAX_LEN + 1u + CHAT_CONTACTS_HEX_PUBLIC_KEY_LEN + 2u)

static chat_contacts_result_t contacts_path(char *out, size_t out_size)
{
    char config_dir[512];
    if (chat_identity_config_dir(config_dir, sizeof(config_dir)) != CHAT_IDENTITY_OK) {
        return CHAT_CONTACTS_ERR_IO;
    }

    int written = snprintf(out, out_size, "%s/%s", config_dir, CHAT_CONTACTS_FILE);
    return written < 0 || (size_t)written >= out_size
        ? CHAT_CONTACTS_ERR_BUFFER
        : CHAT_CONTACTS_OK;
}

static chat_contacts_result_t write_all(int fd, const char *buffer, size_t length)
{
    size_t offset = 0u;
    while (offset < length) {
        ssize_t written = write(fd, &buffer[offset], length - offset);
        if (written <= 0) {
            return CHAT_CONTACTS_ERR_IO;
        }
        offset += (size_t)written;
    }

    return CHAT_CONTACTS_OK;
}

static chat_contacts_result_t parse_contact_line(const char *line,
                                                 char *username,
                                                 size_t username_size,
                                                 unsigned char identity_pk[crypto_sign_PUBLICKEYBYTES])
{
    char hex[CHAT_CONTACTS_HEX_PUBLIC_KEY_LEN];
    char extra = '\0';
    if (sscanf(line, "%32s %64s %c", username, hex, &extra) != 2) {
        return CHAT_CONTACTS_ERR_BAD_FILE;
    }

    if (!chat_username_is_valid(username)) {
        return CHAT_CONTACTS_ERR_BAD_FILE;
    }

    if (strlen(username) + 1u > username_size
        || strlen(hex) != CHAT_CONTACTS_HEX_PUBLIC_KEY_LEN - 1u) {
        return CHAT_CONTACTS_ERR_BAD_FILE;
    }

    size_t bin_len = 0u;
    if (sodium_hex2bin(identity_pk,
                       crypto_sign_PUBLICKEYBYTES,
                       hex,
                       strlen(hex),
                       NULL,
                       &bin_len,
                       NULL) != 0
        || bin_len != crypto_sign_PUBLICKEYBYTES) {
        return CHAT_CONTACTS_ERR_BAD_FILE;
    }

    return CHAT_CONTACTS_OK;
}

static chat_contacts_result_t append_contact(
    const char *path,
    const char *username,
    const unsigned char identity_pk[crypto_sign_PUBLICKEYBYTES])
{
    char hex[CHAT_CONTACTS_HEX_PUBLIC_KEY_LEN];
    (void)sodium_bin2hex(hex, sizeof(hex), identity_pk, crypto_sign_PUBLICKEYBYTES);

    char line[CHAT_CONTACTS_LINE_MAX];
    int written = snprintf(line, sizeof(line), "%s %s\n", username, hex);
    if (written < 0 || (size_t)written >= sizeof(line)) {
        return CHAT_CONTACTS_ERR_BUFFER;
    }

    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) {
        return CHAT_CONTACTS_ERR_IO;
    }

    chat_contacts_result_t result = write_all(fd, line, (size_t)written);
    if (close(fd) != 0 && result == CHAT_CONTACTS_OK) {
        result = CHAT_CONTACTS_ERR_IO;
    }

    return result;
}

static chat_contacts_result_t find_contact(
    const char *path,
    const char *username,
    unsigned char out_identity_pk[crypto_sign_PUBLICKEYBYTES],
    int *out_found)
{
    *out_found = 0;

    FILE *file = fopen(path, "r");
    if (file == NULL) {
        return errno == ENOENT ? CHAT_CONTACTS_OK : CHAT_CONTACTS_ERR_IO;
    }

    chat_contacts_result_t result = CHAT_CONTACTS_OK;
    char line[CHAT_CONTACTS_LINE_MAX];
    while (fgets(line, sizeof(line), file) != NULL) {
        char stored_username[CHAT_USERNAME_MAX_LEN + 1u];
        unsigned char stored_pk[crypto_sign_PUBLICKEYBYTES];
        result = parse_contact_line(line,
                                    stored_username,
                                    sizeof(stored_username),
                                    stored_pk);
        if (result != CHAT_CONTACTS_OK) {
            sodium_memzero(stored_pk, sizeof(stored_pk));
            (void)fclose(file);
            return result;
        }

        if (strcmp(stored_username, username) == 0) {
            memcpy(out_identity_pk, stored_pk, crypto_sign_PUBLICKEYBYTES);
            *out_found = 1;
            sodium_memzero(stored_pk, sizeof(stored_pk));
            (void)fclose(file);
            return CHAT_CONTACTS_OK;
        }

        sodium_memzero(stored_pk, sizeof(stored_pk));
    }

    if (ferror(file)) {
        result = CHAT_CONTACTS_ERR_IO;
    }

    (void)fclose(file);
    return result;
}

const char *chat_contacts_result_name(chat_contacts_result_t result)
{
    switch (result) {
    case CHAT_CONTACTS_OK:
        return "ok";
    case CHAT_CONTACTS_ERR_INVALID:
        return "invalid contact";
    case CHAT_CONTACTS_ERR_IO:
        return "contact storage I/O error";
    case CHAT_CONTACTS_ERR_BUFFER:
        return "contact buffer too small";
    case CHAT_CONTACTS_ERR_BAD_FILE:
        return "invalid contacts file";
    case CHAT_CONTACTS_ERR_MISMATCH:
        return "identity mismatch";
    case CHAT_CONTACTS_ERR_NOT_FOUND:
        return "contact not found";
    }

    return "unknown contacts error";
}

chat_contacts_result_t chat_contacts_verify_or_pin(
    const char *username,
    const unsigned char identity_pk[crypto_sign_PUBLICKEYBYTES],
    int *out_new_contact)
{
    if (!chat_username_is_valid(username) || identity_pk == NULL) {
        return CHAT_CONTACTS_ERR_INVALID;
    }

    if (out_new_contact != NULL) {
        *out_new_contact = 0;
    }

    char path[1024];
    chat_contacts_result_t result = contacts_path(path, sizeof(path));
    if (result != CHAT_CONTACTS_OK) {
        return result;
    }

    unsigned char stored_pk[crypto_sign_PUBLICKEYBYTES];
    int found = 0;
    result = find_contact(path, username, stored_pk, &found);
    if (result != CHAT_CONTACTS_OK) {
        sodium_memzero(stored_pk, sizeof(stored_pk));
        return result;
    }

    if (found) {
        int matches = sodium_memcmp(stored_pk, identity_pk, sizeof(stored_pk)) == 0;
        sodium_memzero(stored_pk, sizeof(stored_pk));
        return matches ? CHAT_CONTACTS_OK : CHAT_CONTACTS_ERR_MISMATCH;
    }

    result = append_contact(path, username, identity_pk);
    if (result == CHAT_CONTACTS_OK && out_new_contact != NULL) {
        *out_new_contact = 1;
    }
    return result;
}

chat_contacts_result_t chat_contacts_load_public_key(
    const char *username,
    unsigned char out_identity_pk[crypto_sign_PUBLICKEYBYTES])
{
    if (!chat_username_is_valid(username) || out_identity_pk == NULL) {
        return CHAT_CONTACTS_ERR_INVALID;
    }

    char path[1024];
    chat_contacts_result_t result = contacts_path(path, sizeof(path));
    if (result != CHAT_CONTACTS_OK) {
        return result;
    }

    int found = 0;
    result = find_contact(path, username, out_identity_pk, &found);
    if (result != CHAT_CONTACTS_OK) {
        return result;
    }

    return found ? CHAT_CONTACTS_OK : CHAT_CONTACTS_ERR_NOT_FOUND;
}
