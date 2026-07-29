// Golden factory: run DPDK's own rte_net_get_ptype() over each corpus
// packet and emit a GoldenFile JSON on stdout (schema consumed by
// src/oracle/dpdk_ptype.rs). Unlike the flow-dissector factory this is
// unprivileged: rte_net_get_ptype is a pure function over mbuf data, so
// a hand-built single-segment stack mbuf suffices — no EAL init, no
// hugepages, no privilege.
//
// Every packet gets a classification (there is no drop verdict in
// rte_net_get_ptype); truncated-Ethernet packets yield ptype 0.
// hdr_lens is zero-initialized before each call because the function
// only writes the fields on the taken path.
//
// Usage: capture <corpus.txt>
#include <rte_mbuf.h>
#include <rte_mbuf_ptype.h>
#include <rte_net.h>
#include <rte_version.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>

static int is_hex(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

// hex string -> bytes; returns length, or -1 on odd-length/invalid input.
static int unhex(const char *s, unsigned char *out, int cap) {
    int n = 0;
    while (s[0] && s[0] != '\n') {
        if (!is_hex(s[0]) || !is_hex(s[1])) return -1;
        if (n >= cap) return -1;
        unsigned v;
        sscanf(s, "%2x", &v);
        out[n++] = (unsigned char)v;
        s += 2;
    }
    return n;
}

static void hexcat(char *dst, const unsigned char *b, int n) {
    for (int i = 0; i < n; i++) sprintf(dst + i * 2, "%02x", b[i]);
    dst[n * 2] = 0;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <corpus.txt>\n", argv[0]); return 2; }

    FILE *cf = fopen(argv[1], "r");
    if (!cf) { perror("fopen corpus"); return 1; }

    printf("{\n  \"dpdk_version\": \"%s\",\n  \"entries\": [\n", rte_version());

    char line[8192];
    int first = 1;
    while (fgets(line, sizeof line, cf)) {
        if (line[0] == '\n' || line[0] == '#' || line[0] == 0) continue;
        unsigned char pkt[2048];
        int plen = unhex(line, pkt, sizeof pkt);
        if (plen <= 0) { fprintf(stderr, "bad corpus line: %s", line); return 1; }

        struct rte_mbuf m;
        struct rte_net_hdr_lens hl;
        memset(&m, 0, sizeof m);
        memset(&hl, 0, sizeof hl);
        m.buf_addr = pkt;
        m.buf_len = sizeof pkt;
        m.data_off = 0;
        m.data_len = (uint16_t)plen;
        m.pkt_len = (uint32_t)plen;
        m.nb_segs = 1;
        m.next = NULL;

        uint32_t ptype = rte_net_get_ptype(&m, &hl, RTE_PTYPE_ALL_MASK);

        char name[512];
        if (rte_get_ptype_name(ptype, name, sizeof name) < 0)
            snprintf(name, sizeof name, "?");

        char phex[4200];
        hexcat(phex, pkt, plen);
        printf("%s    {\"packet_hex\": \"%s\", \"ptype\": %u, \"ptype_name\": \"%s\", "
               "\"hdr_lens\": {\"l2_len\": %u, \"l3_len\": %u, \"l4_len\": %u, "
               "\"tunnel_len\": %u, \"inner_l2_len\": %u, \"inner_l3_len\": %u, "
               "\"inner_l4_len\": %u}}",
               first ? "" : ",\n", phex, ptype, name,
               hl.l2_len, hl.l3_len, hl.l4_len, hl.tunnel_len,
               hl.inner_l2_len, hl.inner_l3_len, hl.inner_l4_len);
        first = 0;
    }
    fclose(cf);
    printf("\n  ]\n}\n");
    return 0;
}
