// Katran golden factory (phase-1 smoke harness): load the pinned
// upstream balancer.bpf.o (GPL — fetched+built at capture time, never
// committed) and BPF_PROG_TEST_RUN each corpus packet through the XDP
// entry, emitting verdict + output packet per line as JSON.
//
// Map state: everything starts empty (array maps zero-initialized) —
// enough for the whole parse path: no-vip TCP/UDP -> XDP_PASS,
// malformed/frag/options -> XDP_DROP, ICMP echo -> XDP_TX with the
// mutated reply. The phase-2 design pins the vip/real/server-id config
// that turns on the hint-parse arms.
//
// Usage: capture <balancer.o> <corpus.txt>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/utsname.h>

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

    struct utsname un; uname(&un);
    printf("{\n  \"kernel_version\": \"%s\",\n  \"map_config\": \"empty (phase-1 smoke)\",\n  \"entries\": [\n", un.release);

    FILE *cf = fopen(argv[2], "r");
    if (!cf) { perror("fopen corpus"); return 1; }
    char line[16384];
    int first = 1;
    while (fgets(line, sizeof line, cf)) {
        if (line[0] == '\n' || line[0] == '#' || line[0] == 0) continue;
        unsigned char pkt[4096];
        int plen = unhex(line, pkt, sizeof pkt);
        if (plen <= 0) { fprintf(stderr, "bad corpus line\n"); return 1; }

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
        char phex[8300], ohex[16500];
        hexcat(phex, pkt, plen);
        // Output packet only when the program mutated/kept it (TX);
        // PASS/DROP outputs are the input echoed back — elide for size.
        if (topts.retval == 3) {
            hexcat(ohex, out, topts.data_size_out);
        } else {
            ohex[0] = 0;
        }
        printf("%s    {\"packet_hex\": \"%s\", \"verdict\": \"%s\", \"out_hex\": \"%s\"}",
               first ? "" : ",\n", phex, verdict_str(topts.retval), ohex);
        first = 0;
    }
    fclose(cf);
    printf("\n  ]\n}\n");
    return 0;
}
