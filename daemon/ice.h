#ifndef CHAT_DAEMON_ICE_H
#define CHAT_DAEMON_ICE_H

#include <stddef.h>

#include <nice/agent.h>

#define CHAT_ICE_RECV_MAX 4096u
#define CHAT_ICE_RECV_QUEUE_CAPACITY 8u
#define CHAT_ICE_HOST_MAX 256u
#define CHAT_ICE_TURN_USERNAME_MAX 128u
#define CHAT_ICE_TURN_PASSWORD_MAX 256u

typedef enum {
    CHAT_ICE_OK = 0,
    CHAT_ICE_ERR_INVALID = -1,
    CHAT_ICE_ERR_AGENT = -2,
    CHAT_ICE_ERR_GATHER = -3,
    CHAT_ICE_ERR_SDP = -4,
    CHAT_ICE_ERR_REMOTE = -5,
    CHAT_ICE_ERR_SEND = -6,
    CHAT_ICE_ERR_BUFFER = -7
} chat_ice_result_t;

typedef struct {
    char local_address[CHAT_ICE_HOST_MAX];
    char stun_host[CHAT_ICE_HOST_MAX];
    unsigned int stun_port;
    char turn_host[CHAT_ICE_HOST_MAX];
    unsigned int turn_port;
    char turn_username[CHAT_ICE_TURN_USERNAME_MAX];
    char turn_password[CHAT_ICE_TURN_PASSWORD_MAX];
    int has_stun;
    int has_turn;
    int has_local_address;
    int force_relay;
} chat_ice_config_t;

typedef struct {
    NiceAgent *agent;
    guint stream_id;
    guint component_id;
    int gathering_done;
    int remote_set;
    int ready;
    int failed;
    int selected_pair_known;
    int selected_pair_is_relayed;
    unsigned char recv_queue[CHAT_ICE_RECV_QUEUE_CAPACITY][CHAT_ICE_RECV_MAX];
    size_t recv_lens[CHAT_ICE_RECV_QUEUE_CAPACITY];
    size_t recv_head;
    size_t recv_count;
} chat_ice_session_t;

void chat_ice_session_init(chat_ice_session_t *session);
void chat_ice_session_close(chat_ice_session_t *session);
void chat_ice_config_init(chat_ice_config_t *config);

chat_ice_result_t chat_ice_session_start(chat_ice_session_t *session,
                                         int controlling,
                                         const chat_ice_config_t *config);

chat_ice_result_t chat_ice_session_generate_local_sdp(chat_ice_session_t *session,
                                                      char **out_sdp);
chat_ice_result_t chat_ice_session_set_remote_sdp(chat_ice_session_t *session,
                                                  const char *remote_sdp);
chat_ice_result_t chat_ice_send(chat_ice_session_t *session,
                                const unsigned char *data,
                                size_t data_len);
chat_ice_result_t chat_ice_take_received(chat_ice_session_t *session,
                                         unsigned char *out,
                                         size_t out_size,
                                         size_t *out_len);
int chat_ice_selected_pair_is_relayed(chat_ice_session_t *session, int *out_is_relayed);
void chat_ice_free_string(char *value);
void chat_ice_poll(void);
const char *chat_ice_result_name(chat_ice_result_t result);

#endif
