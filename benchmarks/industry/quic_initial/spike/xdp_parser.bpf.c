// eBPF QUIC deliverable: does Pakeles's GENERATED quic_initial parser
// — the two-field-split varint clusters, unrolled max_depth×states —
// pass the real Linux kernel verifier and agree under
// BPF_PROG_TEST_RUN? DCID extraction from the Initial long header in
// XDP is exactly what QUIC load balancers route on (the katran
// packet-content half this example converts from boundary to claim).
// (The everyday gate runs the same artifact in rbpf, a userspace VM
// with a weaker verifier; this is the kernel's own.)
//
// Same shape as the katran/TLS spikes: the generated core reads a
// contiguous buffer, so a thin wrapper copies a bounded prefix into a
// per-CPU scratch map and stashes {outcome, reason, consumed_bits}.
//
// The generated file is #included so the spike always tracks the
// committed artifact (no drift).
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "parser.bpf.c"

// Ample for every corpus long header (the parse stops before the AEAD
// payload; only the 1200-byte RFC anchor's padding is clipped). 512
// also keeps the copy loop's verifier exploration at the size the TLS
// spike proved out — 2048 blew the 1M-insn budget (E2BIG).
#define SCRATCH_BYTES 512

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u8[SCRATCH_BYTES]);
    __uint(max_entries, 1);
} pk_scratch SEC(".maps");

struct pk_result {
    __u8 outcome;
    __u16 reason;
    __u64 consumed_bits;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct pk_result);
    __uint(max_entries, 1);
} pk_out SEC(".maps");

SEC("xdp")
int pk_xdp_parse(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u32 z = 0;

    __u8 *buf = bpf_map_lookup_elem(&pk_scratch, &z);
    if (!buf)
        return XDP_ABORTED;

    __u32 n = 0;
#pragma clang loop unroll(disable)
    for (__u32 i = 0; i < SCRATCH_BYTES; i++) {
        if (data + i + 1 > data_end)
            break;
        buf[i] = *((__u8 *)data + i);
        n = i + 1;
    }

    pk_quic_initial_result_t r = {0};
    pk_quic_initial_parse_core(buf, (__u64)n * 8, &r);

    struct pk_result *o = bpf_map_lookup_elem(&pk_out, &z);
    if (!o)
        return XDP_ABORTED;
    o->outcome = r.outcome;
    o->reason = r.reason;
    o->consumed_bits = r.consumed_bits;
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
