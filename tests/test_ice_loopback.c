#define _POSIX_C_SOURCE 200809L

#include "daemon/ice.h"

#include <assert.h>
#include <time.h>

static void spin_ice(void)
{
    chat_ice_poll();
    struct timespec sleep_time = {.tv_sec = 0, .tv_nsec = 10 * 1000 * 1000};
    (void)nanosleep(&sleep_time, NULL);
}

static void wait_for_gathering(chat_ice_session_t *left, chat_ice_session_t *right)
{
    for (int i = 0; i < 500; ++i) {
        if (left->gathering_done && right->gathering_done) {
            return;
        }
        spin_ice();
    }

    assert(0 && "ICE gathering timed out");
}

static void wait_for_ready(chat_ice_session_t *left, chat_ice_session_t *right)
{
    for (int i = 0; i < 1500; ++i) {
        if (left->ready && right->ready) {
            return;
        }
        assert(!left->failed);
        assert(!right->failed);
        spin_ice();
    }

    assert(0 && "ICE connection timed out");
}

int main(void)
{
    chat_ice_session_t left;
    chat_ice_session_t right;
    chat_ice_session_init(&left);
    chat_ice_session_init(&right);

    assert(chat_ice_session_start(&left, 1, NULL) == CHAT_ICE_OK);
    assert(chat_ice_session_start(&right, 0, NULL) == CHAT_ICE_OK);

    wait_for_gathering(&left, &right);

    char *left_sdp = NULL;
    char *right_sdp = NULL;
    assert(chat_ice_session_generate_local_sdp(&left, &left_sdp) == CHAT_ICE_OK);
    assert(chat_ice_session_generate_local_sdp(&right, &right_sdp) == CHAT_ICE_OK);

    assert(chat_ice_session_set_remote_sdp(&left, right_sdp) == CHAT_ICE_OK);
    assert(chat_ice_session_set_remote_sdp(&right, left_sdp) == CHAT_ICE_OK);

    wait_for_ready(&left, &right);

    chat_ice_free_string(left_sdp);
    chat_ice_free_string(right_sdp);
    chat_ice_session_close(&left);
    chat_ice_session_close(&right);
    return 0;
}
