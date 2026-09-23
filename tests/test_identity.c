#define _POSIX_C_SOURCE 200809L

#include "common/identity.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void make_temp_config_dir(char *template, size_t template_size)
{
    int written = snprintf(template, template_size, "/tmp/chat-identity-test-XXXXXX");
    assert(written > 0);
    assert((size_t)written < template_size);
    assert(mkdtemp(template) != NULL);
    assert(setenv(CHAT_CONFIG_DIR_ENV, template, 1) == 0);
}

static void test_identity_create_load_and_permissions(void)
{
    char config_dir[128];
    make_temp_config_dir(config_dir, sizeof(config_dir));

    char fingerprint[CHAT_IDENTITY_FINGERPRINT_LEN];
    assert(chat_identity_create("alex", NULL, fingerprint, sizeof(fingerprint)) == CHAT_IDENTITY_OK);
    assert(strlen(fingerprint) == CHAT_IDENTITY_FINGERPRINT_LEN - 1u);

    chat_identity_t identity;
    assert(chat_identity_load(&identity) == CHAT_IDENTITY_OK);
    assert(strcmp(identity.username, "alex") == 0);

    char server_url[CHAT_IDENTITY_SERVER_URL_MAX];
    assert(chat_identity_load_server_url(server_url, sizeof(server_url)) == CHAT_IDENTITY_OK);
    assert(strcmp(server_url, CHAT_DEFAULT_SERVER_URL) == 0);

    char config_path[256];
    int config_written = snprintf(config_path, sizeof(config_path), "%s/config.toml", config_dir);
    assert(config_written > 0);
    assert((size_t)config_written < sizeof(config_path));
    FILE *config = fopen(config_path, "a");
    assert(config != NULL);
    assert(fputs("ice_force_relay = \"true\"\n", config) >= 0);
    assert(fclose(config) == 0);

    assert(chat_identity_set_server_url("ws://127.0.0.1:8787") == CHAT_IDENTITY_OK);
    assert(chat_identity_load_server_url(server_url, sizeof(server_url)) == CHAT_IDENTITY_OK);
    assert(strcmp(server_url, "ws://127.0.0.1:8787") == 0);

    char preserved_value[16];
    assert(chat_identity_load_config_value("ice_force_relay",
                                           preserved_value,
                                           sizeof(preserved_value)) == CHAT_IDENTITY_OK);
    assert(strcmp(preserved_value, "true") == 0);

    assert(chat_identity_set_server_url("https://example.org")
        == CHAT_IDENTITY_ERR_INVALID_SERVER_URL);
    assert(chat_identity_set_server_url("wss://") == CHAT_IDENTITY_ERR_INVALID_SERVER_URL);
    assert(chat_identity_set_server_url("wss://example.org\"\nusername = \"attacker")
        == CHAT_IDENTITY_ERR_INVALID_SERVER_URL);
    assert(chat_identity_load_server_url(server_url, sizeof(server_url)) == CHAT_IDENTITY_OK);
    assert(strcmp(server_url, "ws://127.0.0.1:8787") == 0);

    char key_path[256];
    int written = snprintf(key_path, sizeof(key_path), "%s/identity.key", config_dir);
    assert(written > 0);
    assert((size_t)written < sizeof(key_path));

    struct stat st;
    assert(stat(key_path, &st) == 0);
    assert((st.st_mode & 0777) == 0600);

    char loaded_fingerprint[CHAT_IDENTITY_FINGERPRINT_LEN];
    assert(chat_identity_fingerprint(identity.public_key, loaded_fingerprint, sizeof(loaded_fingerprint))
        == CHAT_IDENTITY_OK);
    assert(strcmp(fingerprint, loaded_fingerprint) == 0);

    chat_identity_wipe(&identity);
    assert(chat_identity_create("alex", NULL, fingerprint, sizeof(fingerprint))
        == CHAT_IDENTITY_ERR_ALREADY_EXISTS);
}

static void test_identity_rejects_invalid_username(void)
{
    char config_dir[128];
    make_temp_config_dir(config_dir, sizeof(config_dir));

    char fingerprint[CHAT_IDENTITY_FINGERPRINT_LEN];
    assert(chat_identity_create("ab", NULL, fingerprint, sizeof(fingerprint))
        == CHAT_IDENTITY_ERR_INVALID_USERNAME);
}

int main(void)
{
    test_identity_create_load_and_permissions();
    test_identity_rejects_invalid_username();
    return 0;
}
