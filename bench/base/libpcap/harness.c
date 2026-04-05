#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>

extern uint8_t  *__afl_fuzz_ptr;
extern uint32_t *__afl_fuzz_len;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    __afl_fuzz_ptr = (uint8_t *)data;
    static uint32_t current_size;
    current_size = (uint32_t)size;
    __afl_fuzz_len = &current_size;

    if (size < 1)
        return 0;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_dead(DLT_EN10MB, 65535);
    if (!pcap)
        return 0;

    struct pcap_pkthdr h;
    memset(&h, 0, sizeof(h));
    h.caplen = size;
    h.len = size;
    h.ts.tv_sec = 0;
    h.ts.tv_usec = 0;

    // libpcap doesn't have a direct "parse this buffer" without a file or live interface easily
    // but we can use pcap_offline_read or similar if we use a memory-backed file, 
    // or just use internal parsing functions if exposed.
    // Actually, pcap_open_offline expects a file. 
    // Let's use fmemopen to create a file handle from the buffer.

    FILE *f = fmemopen((void *)data, size, "rb");
    if (f) {
        pcap_t *p = pcap_fopen_offline(f, errbuf);
        if (p) {
            const u_char *pkt_data;
            struct pcap_pkthdr *header;
            while (pcap_next_ex(p, &header, &pkt_data) > 0) {
                // do nothing, just parse
            }
            pcap_close(p);
        }
        // f is closed by pcap_close if using pcap_fopen_offline? 
        // Docs say pcap_close closes the file.
    }

    pcap_close(pcap);
    return 0;
}
