#include "daemon/ice.h"

#include "common/log.h"

#include <glib.h>
#include <glib-object.h>
#include <sodium.h>
#include <string.h>

static void on_candidate_gathering_done(NiceAgent *agent,
                                        guint stream_id,
                                        gpointer user_data)
{
    (void)agent;

    chat_ice_session_t *session = user_data;
    if (session == NULL || stream_id != session->stream_id) {
        return;
    }

    session->gathering_done = 1;
    chat_log(CHAT_LOG_INFO, "ICE candidate gathering done");
}

static void on_component_state_changed(NiceAgent *agent,
                                       guint stream_id,
                                       guint component_id,
                                       guint state,
                                       gpointer user_data)
{
    (void)agent;

    chat_ice_session_t *session = user_data;
    if (session == NULL
        || stream_id != session->stream_id
        || component_id != session->component_id) {
        return;
    }

    const char *state_name = nice_component_state_to_string((NiceComponentState)state);
    chat_log(CHAT_LOG_INFO, "ICE component state: %s", state_name);

    if (state == NICE_COMPONENT_STATE_READY || state == NICE_COMPONENT_STATE_CONNECTED) {
        session->ready = 1;
        NiceCandidate *local = NULL;
        NiceCandidate *remote = NULL;
        if (nice_agent_get_selected_pair(agent, stream_id, component_id, &local, &remote)) {
            session->selected_pair_known = 1;
            session->selected_pair_is_relayed =
                (local != NULL && local->type == NICE_CANDIDATE_TYPE_RELAYED)
                || (remote != NULL && remote->type == NICE_CANDIDATE_TYPE_RELAYED);
            chat_log(CHAT_LOG_INFO,
                     "ICE selected pair: local=%s remote=%s",
                     local != NULL ? nice_candidate_type_to_string(local->type) : "unknown",
                     remote != NULL ? nice_candidate_type_to_string(remote->type) : "unknown");
        }
    } else if (state == NICE_COMPONENT_STATE_FAILED) {
        session->failed = 1;
    }
}

static void on_recv(NiceAgent *agent,
                    guint stream_id,
                    guint component_id,
                    guint len,
                    gchar *buf,
                    gpointer user_data)
{
    (void)agent;
    (void)stream_id;
    (void)component_id;

    chat_ice_session_t *session = user_data;
    if (session == NULL || buf == NULL || len > CHAT_ICE_RECV_MAX) {
        if (session != NULL) {
            session->failed = 1;
        }
        return;
    }

    if (session->recv_count >= CHAT_ICE_RECV_QUEUE_CAPACITY) {
        chat_log(CHAT_LOG_WARN, "ICE receive queue full; dropping oldest packet");
        sodium_memzero(session->recv_queue[session->recv_head],
                       session->recv_lens[session->recv_head]);
        session->recv_lens[session->recv_head] = 0u;
        session->recv_head = (session->recv_head + 1u) % CHAT_ICE_RECV_QUEUE_CAPACITY;
        session->recv_count--;
    }

    size_t index = (session->recv_head + session->recv_count) % CHAT_ICE_RECV_QUEUE_CAPACITY;
    memcpy(session->recv_queue[index], buf, len);
    session->recv_lens[index] = len;
    session->recv_count++;
}

void chat_ice_session_init(chat_ice_session_t *session)
{
    if (session == NULL) {
        return;
    }

    memset(session, 0, sizeof(*session));
    session->component_id = NICE_COMPONENT_TYPE_RTP;
}

void chat_ice_session_close(chat_ice_session_t *session)
{
    if (session == NULL) {
        return;
    }

    if (session->agent != NULL) {
        if (session->stream_id != 0u) {
            nice_agent_remove_stream(session->agent, session->stream_id);
        }
        g_object_unref(session->agent);
    }

    chat_ice_session_init(session);
}

void chat_ice_config_init(chat_ice_config_t *config)
{
    if (config == NULL) {
        return;
    }

    memset(config, 0, sizeof(*config));
}

chat_ice_result_t chat_ice_session_start(chat_ice_session_t *session,
                                         int controlling,
                                         const chat_ice_config_t *config)
{
    if (session == NULL) {
        return CHAT_ICE_ERR_INVALID;
    }

    chat_ice_session_close(session);

    session->agent = nice_agent_new_full(NULL,
                                         NICE_COMPATIBILITY_RFC5245,
                                         NICE_AGENT_OPTION_REGULAR_NOMINATION);
    if (session->agent == NULL) {
        return CHAT_ICE_ERR_AGENT;
    }

    g_object_set(G_OBJECT(session->agent),
                 "controlling-mode",
                 controlling ? TRUE : FALSE,
                 "force-relay",
                 config != NULL && config->force_relay ? TRUE : FALSE,
                 "ice-tcp",
                 FALSE,
                 "upnp",
                 FALSE,
                 NULL);
    nice_agent_set_software(session->agent, "ProntoChat");

    session->stream_id = nice_agent_add_stream(session->agent, 1u);
    if (session->stream_id == 0u) {
        chat_ice_session_close(session);
        return CHAT_ICE_ERR_AGENT;
    }
    session->component_id = NICE_COMPONENT_TYPE_RTP;

    if (!nice_agent_set_stream_name(session->agent, session->stream_id, "application")) {
        chat_ice_session_close(session);
        return CHAT_ICE_ERR_AGENT;
    }

    if (config != NULL && config->has_local_address) {
        NiceAddress address;
        nice_address_init(&address);
        if (!nice_address_set_from_string(&address, config->local_address)) {
            chat_ice_session_close(session);
            return CHAT_ICE_ERR_AGENT;
        }
        nice_address_set_port(&address, 0u);
        if (!nice_agent_add_local_address(session->agent, &address)) {
            chat_ice_session_close(session);
            return CHAT_ICE_ERR_AGENT;
        }
        chat_log(CHAT_LOG_INFO, "configured ICE local address %s", config->local_address);
    }

    if (config != NULL && config->has_stun) {
        g_object_set(G_OBJECT(session->agent),
                     "stun-server",
                     config->stun_host,
                     "stun-server-port",
                     (guint)config->stun_port,
                     NULL);
        chat_log(CHAT_LOG_INFO, "configured STUN server %s:%u",
                 config->stun_host, config->stun_port);
    }

    if (config != NULL && config->has_turn) {
        if (!nice_agent_set_relay_info(session->agent,
                                       session->stream_id,
                                       session->component_id,
                                       config->turn_host,
                                       (guint)config->turn_port,
                                       config->turn_username,
                                       config->turn_password,
                                       NICE_RELAY_TYPE_TURN_UDP)) {
            chat_ice_session_close(session);
            return CHAT_ICE_ERR_AGENT;
        }
        chat_log(CHAT_LOG_INFO, "configured TURN UDP relay %s:%u",
                 config->turn_host, config->turn_port);
        if (config->force_relay) {
            chat_log(CHAT_LOG_INFO, "forcing ICE traffic through TURN relay");
        }
    }

    g_signal_connect(G_OBJECT(session->agent),
                     "candidate-gathering-done",
                     G_CALLBACK(on_candidate_gathering_done),
                     session);
    g_signal_connect(G_OBJECT(session->agent),
                     "component-state-changed",
                     G_CALLBACK(on_component_state_changed),
                     session);

    if (!nice_agent_attach_recv(session->agent,
                                session->stream_id,
                                session->component_id,
                                NULL,
                                on_recv,
                                session)) {
        chat_ice_session_close(session);
        return CHAT_ICE_ERR_AGENT;
    }

    if (!nice_agent_gather_candidates(session->agent, session->stream_id)) {
        chat_ice_session_close(session);
        return CHAT_ICE_ERR_GATHER;
    }

    return CHAT_ICE_OK;
}

chat_ice_result_t chat_ice_session_generate_local_sdp(chat_ice_session_t *session,
                                                      char **out_sdp)
{
    if (session == NULL || out_sdp == NULL || session->agent == NULL) {
        return CHAT_ICE_ERR_INVALID;
    }

    if (!session->gathering_done) {
        return CHAT_ICE_ERR_GATHER;
    }

    gchar *sdp = nice_agent_generate_local_sdp(session->agent);
    if (sdp == NULL || sdp[0] == '\0') {
        g_free(sdp);
        return CHAT_ICE_ERR_SDP;
    }

    *out_sdp = sdp;
    return CHAT_ICE_OK;
}

chat_ice_result_t chat_ice_session_set_remote_sdp(chat_ice_session_t *session,
                                                  const char *remote_sdp)
{
    if (session == NULL || session->agent == NULL || remote_sdp == NULL) {
        return CHAT_ICE_ERR_INVALID;
    }

    int added = nice_agent_parse_remote_sdp(session->agent, remote_sdp);
    if (added < 0) {
        return CHAT_ICE_ERR_SDP;
    }

    if (added == 0) {
        return CHAT_ICE_ERR_REMOTE;
    }

    session->remote_set = 1;
    chat_log(CHAT_LOG_INFO, "ICE remote SDP applied with %d stream(s)", added);
    return CHAT_ICE_OK;
}

chat_ice_result_t chat_ice_send(chat_ice_session_t *session,
                                const unsigned char *data,
                                size_t data_len)
{
    if (session == NULL || data == NULL) {
        return CHAT_ICE_ERR_INVALID;
    }

    if (!session->ready || session->agent == NULL || data_len == 0u || data_len > CHAT_ICE_RECV_MAX) {
        return CHAT_ICE_ERR_INVALID;
    }

    gint sent = nice_agent_send(session->agent,
                                session->stream_id,
                                session->component_id,
                                (guint)data_len,
                                (const gchar *)data);
    if (sent != (gint)data_len) {
        return CHAT_ICE_ERR_SEND;
    }

    return CHAT_ICE_OK;
}

chat_ice_result_t chat_ice_take_received(chat_ice_session_t *session,
                                         unsigned char *out,
                                         size_t out_size,
                                         size_t *out_len)
{
    if (session == NULL || out == NULL || out_len == NULL) {
        return CHAT_ICE_ERR_INVALID;
    }

    if (session->recv_count == 0u) {
        *out_len = 0u;
        return CHAT_ICE_OK;
    }

    size_t recv_len = session->recv_lens[session->recv_head];
    if (out_size < recv_len) {
        return CHAT_ICE_ERR_BUFFER;
    }

    memcpy(out, session->recv_queue[session->recv_head], recv_len);
    *out_len = recv_len;
    sodium_memzero(session->recv_queue[session->recv_head], recv_len);
    session->recv_lens[session->recv_head] = 0u;
    session->recv_head = (session->recv_head + 1u) % CHAT_ICE_RECV_QUEUE_CAPACITY;
    session->recv_count--;
    return CHAT_ICE_OK;
}

int chat_ice_selected_pair_is_relayed(chat_ice_session_t *session, int *out_is_relayed)
{
    if (session == NULL || out_is_relayed == NULL || !session->selected_pair_known) {
        return 0;
    }

    *out_is_relayed = session->selected_pair_is_relayed;
    return 1;
}

void chat_ice_free_string(char *value)
{
    g_free(value);
}

void chat_ice_poll(void)
{
    while (g_main_context_iteration(NULL, FALSE)) {
    }
}

const char *chat_ice_result_name(chat_ice_result_t result)
{
    switch (result) {
    case CHAT_ICE_OK:
        return "ok";
    case CHAT_ICE_ERR_INVALID:
        return "invalid ICE session";
    case CHAT_ICE_ERR_AGENT:
        return "ICE agent error";
    case CHAT_ICE_ERR_GATHER:
        return "ICE candidate gathering error";
    case CHAT_ICE_ERR_SDP:
        return "ICE SDP error";
    case CHAT_ICE_ERR_REMOTE:
        return "ICE remote candidate error";
    case CHAT_ICE_ERR_SEND:
        return "ICE send error";
    case CHAT_ICE_ERR_BUFFER:
        return "ICE buffer too small";
    }

    return "unknown ICE error";
}
