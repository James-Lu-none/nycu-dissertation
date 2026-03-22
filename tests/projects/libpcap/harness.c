#include <pcap.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;

    // Fuzz filter compilation
    char *filter_str = malloc(size + 1);
    if (filter_str) {
        memcpy(filter_str, data, size);
        filter_str[size] = '\0';
        
        pcap_t *p = pcap_open_dead(DLT_EN10MB, 65535);
        if (p) {
            struct bpf_program fp;
            // Test if filter compiles
            if (pcap_compile(p, &fp, filter_str, 1, PCAP_NETMASK_UNKNOWN) == 0) {
                pcap_freecode(&fp);
            }
            pcap_close(p);
        }
        free(filter_str);
    }

    // Fuzz PCAP file parsing (using fmemopen)
    FILE *f = fmemopen((void *)data, size, "rb");
    if (f) {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t *p = pcap_fopen_offline(f, errbuf);
        if (p) {
            struct pcap_pkthdr *header;
            const u_char *pkt_data;
            while (pcap_next_ex(p, &header, &pkt_data) > 0);
            pcap_close(p);
        } else {
            // fmemopen's file pointer handles it
            fclose(f);
        }
    }

    return 0;
}
