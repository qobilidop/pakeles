#!/usr/bin/env bash
# Fetch katran's BPF sources at the PINNED commit (GPL-2.0 — capture-time
# only, never committed) and materialize the build tree, including the
# pakeles shim for the Meta-internal common/bpf/bpf_net_helpers.h that
# the OSS tree includes but does not ship (only two BE EtherType
# constants are needed).
set -euo pipefail
cd "$(dirname "$0")"

KATRAN_PIN="dd915fd2e21ab333eda302d753c92c8806defc8a"
RAW="https://raw.githubusercontent.com/facebookincubator/katran/${KATRAN_PIN}"

FILES=(
  katran/lib/bpf/balancer.bpf.c
  katran/lib/bpf/balancer_consts.h
  katran/lib/bpf/balancer_helpers.h
  katran/lib/bpf/balancer_kern-tpl.h
  katran/lib/bpf/balancer_kern_flavors-tpl.h
  katran/lib/bpf/balancer_maps.h
  katran/lib/bpf/balancer_structs.h
  katran/lib/bpf/control_data_maps.h
  katran/lib/bpf/csum_helpers.h
  katran/lib/bpf/encap_helpers.h
  katran/lib/bpf/flow_debug.h
  katran/lib/bpf/flow_debug_helpers.h
  katran/lib/bpf/flow_debug_maps.h
  katran/lib/bpf/handle_icmp.h
  katran/lib/bpf/introspection.h
  katran/lib/bpf/pckt_encap.h
  katran/lib/bpf/pckt_parsing.h
  katran/lib/linux_includes/bpf.h
  katran/lib/linux_includes/bpf_common.h
  katran/lib/linux_includes/bpf_endian.h
  katran/lib/linux_includes/bpf_helpers.h
  katran/lib/linux_includes/jhash.h
)

mkdir -p build/tree
for f in "${FILES[@]}"; do
  dst="build/tree/$f"
  if [ ! -s "$dst" ]; then
    mkdir -p "$(dirname "$dst")"
    curl -fsSL "${RAW}/${f}" -o "$dst"
  fi
done

mkdir -p build/tree/common/bpf
cat > build/tree/common/bpf/bpf_net_helpers.h <<'EOF'
/* Pakeles shim for Meta-internal common/bpf/bpf_net_helpers.h, which
 * katran's OSS tree includes but does not ship. Only the identifiers
 * the balancer build actually needs are provided. */
#pragma once
#define BE_ETH_P_IP 0x0008   /* htons(ETH_P_IP 0x0800) */
#define BE_ETH_P_IPV6 0xdd86 /* htons(ETH_P_IPV6 0x86DD) */
EOF

# --- pakeles observation patch (anchored, sha-verified, idempotent) ---
# Exports the parsed packet_description + QUIC parse result via a
# 1-entry array map, at three points: post-L3/ICMP, post-L4 (both
# BEFORE any vip/LB stage), and after parse_quic. Our code, never
# upstreamed; anchors verified against the pinned source hash.
python3 - <<'PY'
import hashlib, sys

p = "build/tree/katran/lib/bpf/balancer.bpf.c"
src = open(p).read()
if "pk_export_map" in src:
    print("observation patch already applied")
    sys.exit(0)
sha = hashlib.sha256(src.encode()).hexdigest()
EXPECT = "a035fcb30e19466e9e2e2e71c58bf8a93b90b32e9389bc0cca5b25d3fac1b16d"
assert sha == EXPECT, f"pristine balancer.bpf.c drifted: {sha}"

INSTR = '''
/* ---- pakeles observation instrumentation (capture-time only) ---- */
struct pk_export {
  struct packet_description pckt;
  int quic_server_id;
  __u8 quic_cid_version;
  __u8 quic_is_initial;
  __u8 stage; /* bit 1: post-L3/ICMP; bit 2: post-L4; bit 4: quic parsed */
};
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, struct pk_export);
  __uint(max_entries, 1);
} pk_export_map SEC(".maps");
__attribute__((__always_inline__)) static inline void pk_export_stage(
    struct packet_description* pckt, __u8 stage) {
  __u32 z = 0;
  struct pk_export* e = bpf_map_lookup_elem(&pk_export_map, &z);
  if (!e) {
    return;
  }
  e->pckt = *pckt;
  e->stage |= stage;
}
__attribute__((__always_inline__)) static inline void pk_export_quic(
    struct quic_parse_result* q) {
  __u32 z = 0;
  struct pk_export* e = bpf_map_lookup_elem(&pk_export_map, &z);
  if (!e) {
    return;
  }
  e->quic_server_id = q->server_id;
  e->quic_cid_version = q->cid_version;
  e->quic_is_initial = q->is_initial;
  e->stage |= 4;
}
/* ---- end pakeles instrumentation ---- */
'''

def insert_after(hay, anchor, add):
    assert hay.count(anchor) == 1, f"anchor not unique: {anchor!r}"
    return hay.replace(anchor, anchor + add)

src = insert_after(src, '#include "katran/lib/bpf/pckt_parsing.h"\n', INSTR)
src = insert_after(src, "  protocol = pckt.flow.proto;\n",
                   "  pk_export_stage(&pckt, 1);\n")
anchor2 = "  if (is_ipv6) {\n    memcpy(vip.vipv6, pckt.flow.dstv6, 16);"
assert src.count(anchor2) == 1
src = src.replace(anchor2, "  pk_export_stage(&pckt, 2);\n\n" + anchor2)
src = insert_after(
    src,
    "      struct quic_parse_result qpr = parse_quic(data, data_end, is_ipv6, &pckt);\n",
    "      pk_export_quic(&qpr);\n")

open(p, "w").write(src)
print("observation patch applied")
PY

echo "katran@${KATRAN_PIN} tree ready under build/tree"
