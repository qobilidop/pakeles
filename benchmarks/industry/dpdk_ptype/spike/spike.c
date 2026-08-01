// Generated-C-in-DPDK spike: can the pakeles-generated C99 parser
// (examples/dpdk_ptype/gen/parser.c) serve as/alongside DPDK's software
// ptype classifier?
//
// Three answers, printed in order:
//  1. Correctness: an adapter maps the generated parser's result to
//     (RTE_PTYPE_* mask, rte_net_hdr_lens) and must MATCH
//     rte_net_get_ptype() exactly on every packet it projects.
//  2. Coverage: the generated result is a flat last-instance-wins
//     struct — repeated header instances (stacked tunnels, multi-link
//     ext chains) and reject paths are not reconstructible post-hoc;
//     those are counted and skipped, and are THE spike finding: a real
//     integration should compute the classification inside the parser
//     (metadata assigns) rather than project after the fact.
//  3. Performance: ns/packet over the corpus, generated parser (+
//     adapter) vs rte_net_get_ptype. Container-on-Apple-Silicon numbers
//     are indicative only.
//
// Usage: spike <corpus.txt> [bench_iters]
#include <rte_mbuf.h>
#include <rte_mbuf_ptype.h>
#include <rte_net.h>
#include <rte_version.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "parser.h"

static int is_hex(char c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
         (c >= 'A' && c <= 'F');
}

static int unhex(const char *s, unsigned char *out, int cap) {
  int n = 0;
  while (s[0] && s[0] != '\n') {
    if (!is_hex(s[0]) || !is_hex(s[1]))
      return -1;
    if (n >= cap)
      return -1;
    unsigned v;
    sscanf(s, "%2x", &v);
    out[n++] = (unsigned char)v;
    s += 2;
  }
  return n;
}

typedef struct {
  uint32_t ptype;
  struct rte_net_hdr_lens hl;
} proj_t;

// IPv6 ext-map membership (ptype_l3_ip6's EXT set).
static int ip6_ext(uint8_t nh) {
  return nh == 0 || nh == 43 || nh == 44 || nh == 50 || nh == 51 || nh == 60;
}

// Map the generated parser's flat result onto DPDK's classification by
// replaying rte_net.c's walk over the result slots. Returns 0 on
// success, -1 where the flat result is not reconstructible (reject
// paths; repeated instances — detected by the consumed-bits audit).
static int adapt(const pk_dpdk_ptype_result_t *r, proj_t *o) {
  if (r->outcome != PK_DPDK_PTYPE_ACCEPT)
    return -1;
  memset(o, 0, sizeof *o);
  uint64_t bits = 0;
  int used_ip6_opt = 0, used_frag = 0;

  if (!r->ethernet_present)
    return -1;
  o->ptype = RTE_PTYPE_L2_ETHER;
  o->hl.l2_len = 14;
  bits += 112;
  uint32_t proto = r->ethernet.ethertype;
  int inner = 0; // which section the walk is in
  int gre_seen = 0;

  // L2 tags (outer only; rte_net.c has no tag loop).
  if (proto == 0x8100 && r->vlan_present) {
    o->ptype = RTE_PTYPE_L2_ETHER_VLAN;
    o->hl.l2_len += 4;
    bits += 32;
    proto = r->vlan.proto;
  } else if (proto == 0x88A8 && r->qinq_present) {
    o->ptype = RTE_PTYPE_L2_ETHER_QINQ;
    o->hl.l2_len += 8;
    bits += 64;
    proto = r->qinq.proto;
  } else if (proto == 0x8847 || proto == 0x8848) {
    // MPLS: dead code in 23.11.4 — L2_ETHER only, nothing consumed.
    goto audit;
  }

  for (;;) {
    // L3 of the current section.
    if (proto == 0x0800 && r->ipv4_present && !inner) {
      const pk_dpdk_ptype_ipv4_t *ip = &r->ipv4;
      uint8_t vihl = (uint8_t)(ip->version << 4 | ip->ihl);
      if (vihl == 0x45)
        o->ptype |= RTE_PTYPE_L3_IPV4;
      else if (vihl >= 0x46 && vihl <= 0x4F)
        o->ptype |= RTE_PTYPE_L3_IPV4_EXT;
      o->hl.l3_len = ip->ihl * 4;
      bits += 160 + ip->options_bit_len;
      if (ip->mf_frag_off != 0) {
        o->ptype |= RTE_PTYPE_L4_FRAG;
        goto audit;
      }
      proto = ip->protocol;
    } else if (proto == 0x86DD && r->ipv6_present && !inner) {
      o->ptype |= ip6_ext(r->ipv6.next_header) ? RTE_PTYPE_L3_IPV6_EXT
                                               : RTE_PTYPE_L3_IPV6;
      o->hl.l3_len = 40;
      bits += 320;
      proto = r->ipv6.next_header;
      while (proto == 0 || proto == 43 || proto == 60) {
        if (used_ip6_opt++ || !r->ipv6_ext_opt_present)
          return -1;
        o->hl.l3_len += (uint32_t)(1 + r->ipv6_ext_opt.hdr_ext_len) * 8;
        bits += 16 + r->ipv6_ext_opt.body_bit_len;
        proto = r->ipv6_ext_opt.next_header;
      }
      if (proto == 44) {
        if (used_frag++ || !r->ipv6_frag_present)
          return -1;
        o->hl.l3_len += 8;
        bits += 64;
        if (r->ipv6_frag.next_header != 0)
          o->ptype |= RTE_PTYPE_L4_FRAG;
        goto audit;
      }
    } else if (inner && proto == 0x0800 && r->ipv4_present) {
      const pk_dpdk_ptype_ipv4_t *ip = &r->ipv4;
      uint8_t vihl = (uint8_t)(ip->version << 4 | ip->ihl);
      if (vihl == 0x45)
        o->ptype |= RTE_PTYPE_INNER_L3_IPV4;
      else if (vihl >= 0x46 && vihl <= 0x4F)
        o->ptype |= RTE_PTYPE_INNER_L3_IPV4_EXT;
      o->hl.inner_l3_len = ip->ihl * 4;
      bits += 160 + ip->options_bit_len;
      if (ip->mf_frag_off != 0) {
        o->ptype |= RTE_PTYPE_INNER_L4_FRAG;
        goto audit;
      }
      proto = ip->protocol;
    } else if (inner && proto == 0x86DD && r->ipv6_present) {
      o->ptype |= ip6_ext(r->ipv6.next_header) ? RTE_PTYPE_INNER_L3_IPV6_EXT
                                               : RTE_PTYPE_INNER_L3_IPV6;
      o->hl.inner_l3_len = 40;
      bits += 320;
      proto = r->ipv6.next_header;
      while (proto == 0 || proto == 43 || proto == 60) {
        if (used_ip6_opt++ || !r->ipv6_ext_opt_present)
          return -1;
        o->hl.inner_l3_len += (uint32_t)(1 + r->ipv6_ext_opt.hdr_ext_len) * 8;
        bits += 16 + r->ipv6_ext_opt.body_bit_len;
        proto = r->ipv6_ext_opt.next_header;
      }
      if (proto == 44) {
        if (used_frag++ || !r->ipv6_frag_present)
          return -1;
        o->hl.inner_l3_len += 8;
        bits += 64;
        if (r->ipv6_frag.next_header != 0)
          o->ptype |= RTE_PTYPE_INNER_L4_FRAG;
        goto audit;
      }
    } else {
      // No L3 consumed in this section; fall through to the
      // dispatch below with the leftover proto.
    }

    // L4 / tunnel / inner dispatch on the leftover proto.
    if (!inner) {
      if (proto == 6 && r->tcp_present) {
        o->ptype |= RTE_PTYPE_L4_TCP;
        o->hl.l4_len = (uint32_t)r->tcp.data_offset * 4;
        bits += 160;
        goto audit;
      }
      if (proto == 17) {
        o->ptype |= RTE_PTYPE_L4_UDP;
        o->hl.l4_len = 8;
        goto audit;
      }
      if (proto == 132) {
        o->ptype |= RTE_PTYPE_L4_SCTP;
        o->hl.l4_len = 12;
        goto audit;
      }
      // Tunnel arms (incl. the LE byte-swap EtherTypes).
      if (proto == 47 || proto == 0x2F00) {
        if (!r->gre_present)
          return -1;
        bits += 32;
        if (r->gre.r)
          goto audit; // R=1: not a tunnel
        if (!r->gre_opt_present)
          return -1;
        gre_seen = 1;
        o->hl.tunnel_len = 4 + 4u * (r->gre.c + r->gre.k + r->gre.s);
        bits += r->gre_opt.body_bit_len;
        o->ptype |= (r->gre.proto == 0x6558) ? RTE_PTYPE_TUNNEL_NVGRE
                                             : RTE_PTYPE_TUNNEL_GRE;
        proto = r->gre.proto;
      } else if (proto == 4 || proto == 0x0400) {
        o->ptype |= RTE_PTYPE_TUNNEL_IP;
        proto = 0x0800;
      } else if (proto == 41 || proto == 0x2900) {
        o->ptype |= RTE_PTYPE_TUNNEL_IP;
        proto = 0x86DD;
      } else if (proto == 8) {
        proto = 0x0800; // LE: u8 8 == be16(0x0800), no tunnel bit
      } else if (proto == 129) {
        proto = 0x8100; // LE: u8 129 == be16(0x8100)
      } else if (proto != 0x6558 && proto != 0x8100 && proto != 0x88A8) {
        goto audit; // nothing else classifies
      }
      inner = 1;
      // Inner L2.
      if (proto == 0x6558) {
        if (!r->ethernet_present)
          return -1; // shared slot: repeat
        return -1;   // inner Ethernet reuses the ethernet slot — lost
      }
      if (proto == 0x8100) {
        if (!r->vlan_present || o->hl.l2_len > 14)
          return -1; // slot reuse check
        o->ptype = (o->ptype & ~RTE_PTYPE_INNER_L2_MASK) |
                   RTE_PTYPE_INNER_L2_ETHER_VLAN;
        o->hl.inner_l2_len += 4;
        bits += 32;
        proto = r->vlan.proto;
      } else if (proto == 0x88A8) {
        if (!r->qinq_present || o->hl.l2_len > 14)
          return -1;
        o->ptype = (o->ptype & ~RTE_PTYPE_INNER_L2_MASK) |
                   RTE_PTYPE_INNER_L2_ETHER_QINQ;
        o->hl.inner_l2_len += 8;
        bits += 64;
        proto = r->qinq.proto;
      }
      continue; // inner L3 pass
    }
    // Inner L4.
    if (proto == 6 && r->tcp_present) {
      o->ptype |= RTE_PTYPE_INNER_L4_TCP;
      o->hl.inner_l4_len = (uint32_t)r->tcp.data_offset * 4;
      bits += 160;
    } else if (proto == 17) {
      o->ptype |= RTE_PTYPE_INNER_L4_UDP;
      o->hl.inner_l4_len = 8;
    } else if (proto == 132) {
      o->ptype |= RTE_PTYPE_INNER_L4_SCTP;
      o->hl.inner_l4_len = 12;
    }
    goto audit;
  }

audit:
  // The repeat detector: if any instance was extracted more than once
  // (stacked tunnels, TEB, multi-link ext chains), the flat result's
  // slots were overwritten and the walk above under-counts.
  if (bits != r->consumed_bits)
    return -1;
  if (gre_seen && o->hl.tunnel_len != 4 + r->gre_opt.body_bit_len / 8)
    return -1;
  return 0;
}

static uint64_t now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

#define MAX_PKTS 8192

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s <corpus.txt> [bench_iters]\n", argv[0]);
    return 2;
  }
  long iters = argc > 2 ? atol(argv[2]) : 200000;

  static unsigned char pkts[MAX_PKTS][4096];
  static int lens[MAX_PKTS];
  int n = 0;

  FILE *cf = fopen(argv[1], "r");
  if (!cf) {
    perror("fopen corpus");
    return 1;
  }
  char line[262144];
  while (fgets(line, sizeof line, cf) && n < MAX_PKTS) {
    if (line[0] == '\n' || line[0] == '#' || line[0] == 0)
      continue;
    int plen = unhex(line, pkts[n], sizeof pkts[n]);
    if (plen <= 0)
      continue; // oversized witnesses: bench corpus only
    lens[n++] = plen;
  }
  fclose(cf);
  printf("spike: %d packets, %s\n", n, rte_version());

  // 1+2. Correctness + coverage of the post-hoc adapter.
  int projected = 0, skipped = 0, mismatches = 0;
  for (int i = 0; i < n; i++) {
    struct rte_mbuf m;
    struct rte_net_hdr_lens hl;
    memset(&m, 0, sizeof m);
    memset(&hl, 0, sizeof hl);
    m.buf_addr = pkts[i];
    m.buf_len = sizeof pkts[i];
    m.data_len = (uint16_t)lens[i];
    m.pkt_len = (uint32_t)lens[i];
    m.nb_segs = 1;
    uint32_t want = rte_net_get_ptype(&m, &hl, RTE_PTYPE_ALL_MASK);

    pk_dpdk_ptype_result_t res;
    pk_dpdk_ptype_parse(pkts[i], (uint64_t)lens[i] * 8, &res);
    proj_t got;
    if (adapt(&res, &got) != 0) {
      skipped++;
      continue;
    }
    projected++;
    if (got.ptype != want || memcmp(&got.hl, &hl, sizeof hl) != 0) {
      mismatches++;
      printf(
          "  MISMATCH pkt %d: ours=%#x dpdk=%#x (lens %u/%u/%u/%u/%u/%u/%u vs "
          "%u/%u/%u/%u/%u/%u/%u)\n",
          i, got.ptype, want, got.hl.l2_len, got.hl.l3_len, got.hl.l4_len,
          got.hl.tunnel_len, got.hl.inner_l2_len, got.hl.inner_l3_len,
          got.hl.inner_l4_len, hl.l2_len, hl.l3_len, hl.l4_len, hl.tunnel_len,
          hl.inner_l2_len, hl.inner_l3_len, hl.inner_l4_len);
    }
  }
  printf("adapter: %d projected (all must match), %d skipped (reject paths + "
         "repeated-instance "
         "shapes), %d mismatches\n",
         projected, skipped, mismatches);

  // 3. Benchmark: whole-corpus round-robin.
  if (iters <= 0)
    return mismatches == 0 ? 0 : 1;
  volatile uint32_t sink = 0;
  uint64_t t0 = now_ns();
  for (long it = 0; it < iters; it++) {
    int i = (int)(it % n);
    struct rte_mbuf m;
    struct rte_net_hdr_lens hl;
    memset(&m, 0, sizeof m);
    m.buf_addr = pkts[i];
    m.buf_len = sizeof pkts[i];
    m.data_len = (uint16_t)lens[i];
    m.pkt_len = (uint32_t)lens[i];
    m.nb_segs = 1;
    sink += rte_net_get_ptype(&m, &hl, RTE_PTYPE_ALL_MASK);
  }
  uint64_t t1 = now_ns();
  for (long it = 0; it < iters; it++) {
    int i = (int)(it % n);
    pk_dpdk_ptype_result_t res;
    sink += (uint32_t)pk_dpdk_ptype_parse(pkts[i], (uint64_t)lens[i] * 8, &res);
  }
  uint64_t t2 = now_ns();
  for (long it = 0; it < iters; it++) {
    int i = (int)(it % n);
    pk_dpdk_ptype_result_t res;
    pk_dpdk_ptype_parse(pkts[i], (uint64_t)lens[i] * 8, &res);
    proj_t got;
    sink += (uint32_t)adapt(&res, &got);
  }
  uint64_t t3 = now_ns();
  (void)sink;
  double a = (double)(t1 - t0) / (double)iters;
  double b = (double)(t2 - t1) / (double)iters;
  double c = (double)(t3 - t2) / (double)iters;
  printf("bench (%ld iters, corpus round-robin, ns/packet):\n", iters);
  printf("  rte_net_get_ptype:        %8.1f\n", a);
  printf("  generated parser:         %8.1f  (%+.1f%%)\n", b,
         100.0 * (b - a) / a);
  printf("  generated parser+adapter: %8.1f  (%+.1f%%)\n", c,
         100.0 * (c - a) / a);
  return mismatches == 0 ? 0 : 1;
}
