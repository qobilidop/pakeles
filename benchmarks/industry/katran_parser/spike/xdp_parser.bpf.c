// eBPF deliverable spike: does Pakeles's GENERATED katran_parser parser
// pass the real Linux kernel verifier and produce correct results under
// BPF_PROG_TEST_RUN? (The everyday gate already runs it in rbpf, a
// userspace eBPF VM with a weaker verifier; this is the kernel's own.)
//
// The generated parser core (`pk_katran_parser_parse_core`) reads a
// contiguous buffer of `bit_len` bits. XDP packets are not guaranteed
// contiguous or bounded, so this thin wrapper copies a bounded prefix
// into a per-CPU array-map scratch buffer (BPF stack is 512 B; the
// result struct alone is larger), then calls the generated core and
// stashes {outcome, reason, consumed_bits} for the userspace harness.
//
// The generated file is #included so the spike always tracks the
// committed artifact (no drift).
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Silence the generated file's freestanding typedefs clashing with
// vmlinux/asm types: it defines uintN_t from __UINT*_TYPE__, which is
// self-consistent and independent of linux/bpf.h.
#include "parser.bpf.c"

#define SCRATCH_BYTES 256

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

    // Bounded copy of up to SCRATCH_BYTES: the loop bound is a compile
    // -time constant and every access is < SCRATCH_BYTES, which the
    // verifier can prove.
    __u32 n = 0;
#pragma clang loop unroll(disable)
    for (__u32 i = 0; i < SCRATCH_BYTES; i++) {
        if (data + i + 1 > data_end)
            break;
        buf[i] = *((__u8 *)data + i);
        n = i + 1;
    }

    pk_katran_parser_result_t r = {0};
    pk_katran_parser_parse_core(buf, (__u64)n * 8, &r);

    struct pk_result *o = bpf_map_lookup_elem(&pk_out, &z);
    if (!o)
        return XDP_ABORTED;
    o->outcome = r.outcome;
    o->reason = r.reason;
    o->consumed_bits = r.consumed_bits;
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
