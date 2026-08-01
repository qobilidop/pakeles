// Loads the generated-parser XDP wrapper (verifier runs at load) and
// BPF_PROG_TEST_RUNs each corpus packet, printing the parser outcome per
// line as JSON for cross-check against the pakeles interpreter.
//
// Usage: run <xdp_parser.bpf.o> <corpus.txt>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int is_hex(char c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
         (c >= 'A' && c <= 'F');
}
static int unhex(const char *s, unsigned char *out, int cap) {
  int n = 0;
  while (s[0] && s[0] != '\n') {
    if (!is_hex(s[0]) || !is_hex(s[1]) || n >= cap)
      return -1;
    unsigned v;
    sscanf(s, "%2x", &v);
    out[n++] = (unsigned char)v;
    s += 2;
  }
  return n;
}

struct pk_result {
  uint8_t outcome;
  uint16_t reason;
  uint64_t consumed_bits;
};

int main(int argc, char **argv) {
  if (argc < 3) {
    fprintf(stderr, "usage: %s <obj> <corpus>\n", argv[0]);
    return 2;
  }

  struct bpf_object *obj = bpf_object__open_file(argv[1], NULL);
  if (!obj) {
    fprintf(stderr, "open failed\n");
    return 1;
  }
  // The load is the headline: this is where the kernel verifier runs.
  if (bpf_object__load(obj)) {
    fprintf(stderr, "VERIFIER REJECTED the generated parser (load failed)\n");
    return 3;
  }
  fprintf(stderr, "VERIFIER ACCEPTED the generated parser\n");

  struct bpf_program *p = bpf_object__find_program_by_name(obj, "pk_xdp_parse");
  if (!p) {
    fprintf(stderr, "no pk_xdp_parse\n");
    return 1;
  }
  int prog_fd = bpf_program__fd(p);
  struct bpf_map *om = bpf_object__find_map_by_name(obj, "pk_out");
  if (!om) {
    fprintf(stderr, "no pk_out\n");
    return 1;
  }
  int out_fd = bpf_map__fd(om);

  FILE *cf = fopen(argv[2], "r");
  if (!cf) {
    perror("fopen");
    return 1;
  }
  char line[16384];
  int first = 1;
  printf("[\n");
  while (fgets(line, sizeof line, cf)) {
    if (line[0] == '\n' || line[0] == '#' || line[0] == 0)
      continue;
    unsigned char pkt[4096];
    int plen = unhex(line, pkt, sizeof pkt);
    if (plen < 14)
      continue; // XDP TEST_RUN floor
    unsigned char outbuf[4096];
    LIBBPF_OPTS(bpf_test_run_opts, topts, .data_in = pkt,
                .data_size_in = (uint32_t)plen, .data_out = outbuf,
                .data_size_out = sizeof outbuf, .repeat = 1);
    if (bpf_prog_test_run_opts(prog_fd, &topts)) {
      fprintf(stderr, "TEST_RUN failed\n");
      return 1;
    }
    uint32_t z = 0;
    struct pk_result r;
    memset(&r, 0, sizeof r);
    if (bpf_map_lookup_elem(out_fd, &z, &r)) {
      fprintf(stderr, "map read failed\n");
      return 1;
    }
    printf("%s  {\"outcome\": \"%s\", \"reason\": %u, \"consumed_bits\": %llu}",
           first ? "" : ",\n", r.outcome == 0 ? "accept" : "reject", r.reason,
           (unsigned long long)r.consumed_bits);
    first = 0;
  }
  fclose(cf);
  printf("\n]\n");
  return 0;
}
