// Katran golden factory: load the pinned upstream balancer.bpf.o (GPL —
// fetched+built at capture time, never committed) with the pakeles
// observation patch, BPF_PROG_TEST_RUN each corpus packet through the
// XDP entry, and emit per line: the XDP verdict, the mutated output
// packet (TX only), and the parsed katran flow keys read back from
// pk_export_map (src/dst, ports, proto, flags, tos + QUIC parse result).
//
// The export runs BEFORE any vip/LB stage, so the core parse (L3 + ICMP
// inner + L4 ports/flags) is observable with all maps empty. The
// QUIC/stable-rt/TPR hint arms need the phase-2 vip config (config C) to
// fire — their export bit stays 0 until then.
//
// Usage: capture <balancer.o> <corpus.txt>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/utsname.h>

// Mirrors of the patched structs (balancer_structs.h flow_key /
// packet_description + the pakeles pk_export). Kept in sync by the
// pinned-source assertion in fetch.sh.
struct flow_key {
    uint32_t src[4];
    uint32_t dst[4];
    uint16_t port16[2];
    uint8_t proto;
};
struct packet_description {
    struct flow_key flow;
    uint32_t real_index;
    uint8_t flags;
    uint8_t tos;
};
struct pk_export {
    struct packet_description pckt;
    int32_t quic_server_id;
    uint8_t quic_cid_version;
    uint8_t quic_is_initial;
    uint8_t stage;
};

static int is_hex(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

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

static const char *verdict_str(unsigned v) {
    switch (v) {
        case 0: return "XDP_ABORTED";
        case 1: return "XDP_DROP";
        case 2: return "XDP_PASS";
        case 3: return "XDP_TX";
        case 4: return "XDP_REDIRECT";
        default: return "?";
    }
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s <balancer.o> <corpus.txt>\n", argv[0]); return 2; }

    struct bpf_object *obj = bpf_object__open_file(argv[1], NULL);
    if (!obj) { fprintf(stderr, "open %s failed\n", argv[1]); return 1; }
    if (bpf_object__load(obj)) { fprintf(stderr, "load failed (need privilege?)\n"); return 1; }

    struct bpf_program *entry = bpf_object__find_program_by_name(obj, "balancer_ingress");
    if (!entry) { fprintf(stderr, "missing program balancer_ingress — pin drift?\n"); return 1; }
    int prog_fd = bpf_program__fd(entry);

    struct bpf_map *xmap = bpf_object__find_map_by_name(obj, "pk_export_map");
    if (!xmap) { fprintf(stderr, "missing pk_export_map — observation patch not applied?\n"); return 1; }
    int xmap_fd = bpf_map__fd(xmap);

    struct utsname un; uname(&un);
    const char *pin = getenv("KATRAN_PIN");
    printf("{\n  \"katran_commit\": \"%s\",\n  \"kernel_version\": \"%s\",\n"
           "  \"map_config\": \"empty (default build)\",\n  \"entries\": [\n",
           pin ? pin : "unknown", un.release);

    FILE *cf = fopen(argv[2], "r");
    if (!cf) { perror("fopen corpus"); return 1; }
    char line[16384];
    int first = 1;
    while (fgets(line, sizeof line, cf)) {
        if (line[0] == '\n' || line[0] == '#' || line[0] == 0) continue;
        unsigned char pkt[4096];
        int plen = unhex(line, pkt, sizeof pkt);
        if (plen <= 0) { fprintf(stderr, "bad corpus line\n"); return 1; }

        // Zero the export slot before each run so a skipped export reads
        // as stage 0 (keys not reached), never stale from a prior packet.
        uint32_t zero = 0;
        struct pk_export ex;
        memset(&ex, 0, sizeof ex);
        if (bpf_map_update_elem(xmap_fd, &zero, &ex, BPF_ANY)) {
            fprintf(stderr, "pk_export_map reset failed\n"); return 1;
        }

        unsigned char out[8192];
        LIBBPF_OPTS(bpf_test_run_opts, topts,
            .data_in = pkt, .data_size_in = (uint32_t)plen,
            .data_out = out, .data_size_out = sizeof out,
            .repeat = 1,
        );
        if (bpf_prog_test_run_opts(prog_fd, &topts)) {
            fprintf(stderr, "TEST_RUN failed (packet len %d)\n", plen);
            return 1;
        }
        if (bpf_map_lookup_elem(xmap_fd, &zero, &ex)) {
            fprintf(stderr, "pk_export_map lookup failed\n"); return 1;
        }

        char phex[8300], ohex[16500];
        hexcat(phex, pkt, plen);
        if (topts.retval == 3) {
            hexcat(ohex, out, topts.data_size_out);
        } else {
            ohex[0] = 0;
        }

        printf("%s    {\"packet_hex\": \"%s\", \"verdict\": \"%s\", \"out_hex\": \"%s\", "
               "\"stage\": %u",
               first ? "" : ",\n", phex, verdict_str(topts.retval), ohex, ex.stage);
        // Flow keys are meaningful only once the parse reached the export
        // point (stage bit 1). proto decides v4 vs v6 address width.
        if (ex.stage & 1) {
            char src[33] = "", dst[33] = "";
            hexcat(src, (unsigned char *)ex.pckt.flow.src, 16);
            hexcat(dst, (unsigned char *)ex.pckt.flow.dst, 16);
            printf(", \"flow\": {\"src\": \"%s\", \"dst\": \"%s\", "
                   "\"sport\": %u, \"dport\": %u, \"proto\": %u, "
                   "\"flags\": %u, \"tos\": %u, \"l4_reached\": %s}",
                   src, dst,
                   ntohs(ex.pckt.flow.port16[0]), ntohs(ex.pckt.flow.port16[1]),
                   ex.pckt.flow.proto, ex.pckt.flags, ex.pckt.tos,
                   (ex.stage & 2) ? "true" : "false");
        }
        if (ex.stage & 4) {
            printf(", \"quic\": {\"server_id\": %d, \"cid_version\": %u, "
                   "\"is_initial\": %s}",
                   ex.quic_server_id, ex.quic_cid_version,
                   ex.quic_is_initial ? "true" : "false");
        }
        printf("}");
        first = 0;
    }
    fclose(cf);
    printf("\n  ]\n}\n");
    return 0;
}
