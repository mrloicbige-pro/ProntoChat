#ifndef CHAT_CONTACTS_H
#define CHAT_CONTACTS_H

#include <sodium.h>

typedef enum {
    CHAT_CONTACTS_OK = 0,
    CHAT_CONTACTS_ERR_INVALID = -1,
    CHAT_CONTACTS_ERR_IO = -2,
    CHAT_CONTACTS_ERR_BUFFER = -3,
    CHAT_CONTACTS_ERR_BAD_FILE = -4,
    CHAT_CONTACTS_ERR_MISMATCH = -5,
    CHAT_CONTACTS_ERR_NOT_FOUND = -6
} chat_contacts_result_t;

const char *chat_contacts_result_name(chat_contacts_result_t result);

chat_contacts_result_t chat_contacts_verify_or_pin(
    const char *username,
    const unsigned char identity_pk[crypto_sign_PUBLICKEYBYTES],
    int *out_new_contact);

chat_contacts_result_t chat_contacts_load_public_key(
    const char *username,
    unsigned char out_identity_pk[crypto_sign_PUBLICKEYBYTES]);

#endif
