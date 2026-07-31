/* Userspace twin of the XDP harness: runs the SAME committed generated
 * core (gen/parser.c, gate-proven field-equal to the interpreter) over
 * the corpus and prints the same JSON shape — so `run.sh` can diff
 * kernel TEST_RUN outcomes against interpreter semantics line by line.
 * Applies the same >= 14-byte floor and 512-byte prefix cap the XDP
 * lane has, so the comparison is apples to apples. */
#include "parser.h"
#include <stdio.h>
#include <string.h>

static int is_hex(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}
static int unhex(const char *s, unsigned char *out, int cap) {
    int n = 0;
    while (s[0] && s[0] != '\n') {
        if (!is_hex(s[0]) || !is_hex(s[1]) || n >= cap) return -1;
        unsigned v; sscanf(s, "%2x", &v); out[n++] = (unsigned char)v; s += 2;
    }
    return n;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <corpus>\n", argv[0]); return 2; }
    FILE *cf = fopen(argv[1], "r");
    if (!cf) { perror("fopen"); return 1; }
    char line[16384];
    int first = 1;
    printf("[\n");
    while (fgets(line, sizeof line, cf)) {
        if (line[0] == '\n' || line[0] == '#' || line[0] == 0) continue;
        unsigned char pkt[4096];
        int plen = unhex(line, pkt, sizeof pkt);
        if (plen < 14) continue; /* XDP TEST_RUN floor, mirrored */
        if (plen > 512) plen = 512; /* scratch cap, mirrored */
        pk_quic_initial_result_t r;
        memset(&r, 0, sizeof r);
        pk_quic_initial_parse(pkt, (unsigned long long)plen * 8, &r);
        printf("%s  {\"outcome\": \"%s\", \"reason\": %u, \"consumed_bits\": %llu}",
               first ? "" : ",\n", r.outcome == 0 ? "accept" : "reject",
               (unsigned)r.reason, (unsigned long long)r.consumed_bits);
        first = 0;
    }
    fclose(cf);
    printf("\n]\n");
    return 0;
}
