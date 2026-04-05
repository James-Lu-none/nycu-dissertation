#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <ares.h>

extern uint8_t  *__afl_fuzz_ptr;
extern uint32_t *__afl_fuzz_len;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    __afl_fuzz_ptr = (uint8_t *)data;
    static uint32_t current_size;
    current_size = (uint32_t)size;
    __afl_fuzz_len = &current_size;

    if (size < 1) return 0;

    ares_channel channel;
    struct ares_options options;
    int optmask = 0;

    if (ares_init_options(&channel, &options, optmask) != ARES_SUCCESS)
        return 0;

    struct hostent *host = NULL;
    struct ares_addr_node *nodes = NULL;

    // Test various parsing functions
    ares_parse_a_reply(data, (int)size, &host, &nodes, NULL);
    if (host) ares_free_hostent(host);
    if (nodes) ares_free_data(nodes);

    host = NULL;
    ares_parse_aaaa_reply(data, (int)size, &host, NULL, NULL);
    if (host) ares_free_hostent(host);

    struct ares_srv_reply *srv = NULL;
    ares_parse_srv_reply(data, (int)size, &srv);
    if (srv) ares_free_data(srv);

    struct ares_mx_reply *mx = NULL;
    ares_parse_mx_reply(data, (int)size, &mx);
    if (mx) ares_free_data(mx);

    struct ares_txt_reply *txt = NULL;
    ares_parse_txt_reply(data, (int)size, &txt);
    if (txt) ares_free_data(txt);

    ares_destroy(channel);

    return 0;
}
