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

echo "katran@${KATRAN_PIN} tree ready under build/tree"
