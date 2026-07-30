// Depth-sweep twin of xdp_parser.bpf.c: identical wrapper, but the
// generated core comes from PK_SWEEP_SRC so one wrapper serves every
// max_depth variant (see depth-sweep.sh).
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include PK_SWEEP_SRC

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

    pk_tls_clienthello_result_t r = {0};
    pk_tls_clienthello_parse_core(buf, (__u64)n * 8, &r);

    struct pk_result *o = bpf_map_lookup_elem(&pk_out, &z);
    if (!o)
        return XDP_ABORTED;
    o->outcome = r.outcome;
    o->reason = r.reason;
    o->consumed_bits = r.consumed_bits;
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
