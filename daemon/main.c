#include "common/log.h"

#include <glib.h>
#include <stdio.h>

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    chat_log(CHAT_LOG_INFO, "chatd skeleton starting");

    GMainLoop *loop = g_main_loop_new(NULL, FALSE);
    if (loop == NULL) {
        chat_log(CHAT_LOG_ERROR, "failed to create GLib main loop");
        return 1;
    }

    printf("chatd daemon skeleton is ready. Networking is not implemented yet.\n");
    g_main_loop_unref(loop);
    return 0;
}
