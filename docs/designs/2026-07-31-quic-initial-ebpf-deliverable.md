# quic_initial eBPF deliverable — generated QUIC header parser in the real kernel

**Claim.** Pakeles's GENERATED eBPF parser for `quic_initial` — the
QUIC v1 long header with both self-sizing varint clusters — loads
into the real Linux kernel **verifier-clean at the committed
`max_depth` (12, 22 states, no depth reduction needed)** and, under
`BPF_PROG_TEST_RUN`, agrees with the same generated core run in
userspace (gate-proven equal to the interpreter) on **136/136** corpus
lines (151 entries minus 15 under the 14-byte XDP TEST_RUN floor).

Reproduce (privileged container):

    ./dev-priv.sh examples/real_world/quic_initial/spike/run.sh

**Why this is the audience artifact.** DCID extraction from the
Initial long header in XDP is exactly what QUIC load balancers route
on (katran's own QUIC support is the precedent — and its config-gated
QUIC verdict was the documented boundary this example converts into a
packet-content claim). The varint clusters are the part a hand-written
eBPF parser gets wrong: four width arms, composed lengths, and a
token whose size is bounded only by the buffer. Here every masked read
is generated from the same IR the agreement claim is proven on.

**Contrast with tls_clienthello.** TLS needed a depth reduction
(committed 96 → measured ceiling 22) because the unrolled TLV loop
scales the verifier walk. quic_initial's grammar is loop-free (the
varint "loop" is 4 static arms), so the COMMITTED description is
verifier-clean as-is — no sweep, no reduced-depth lane, no caveat.

**One harness finding** (wrapper, not parser): the scratch-copy loop's
size is a real verifier lever. At `SCRATCH_BYTES = 2048` the load
fails E2BIG (>1M instructions explored — each copy-loop exit path
re-walks the parser core); at the TLS-proven 512 it passes with room.
The parse never needs the AEAD payload, so 512 clips nothing but the
RFC anchor's padding. Recorded for the next example that reuses the
spike-wrapper pattern.
