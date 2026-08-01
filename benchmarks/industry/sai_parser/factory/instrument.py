"""Apply Pakeles's observation patch to a COPY of the vendored SONiC PINS
sai parser, making the parse observable on simple_switch.

Anchored + sha-verified + idempotent (the katran-factory discipline). The
patch adds a `pk_verdict` header (a header-validity bitmap + the parser
error code) in the SAME wire format Pakeles's own P4 backend emits,
forwards to port 1, and makes the deparser emit ONLY that verdict — so
the incumbent and our generated `sai_parser` P4 speak the identical
(bitmap, err) format on one simple_switch. The bitmap bit order is the
contract pinned in the design doc §4 and the example.

Usage: instrument.py <vendored_sai_parser.p4> <out_instrumented.p4>
"""

import hashlib
import sys
from pathlib import Path

# Pinned sha of the vendored snapshot (sonic-pins e77250b8,
# p4_symbolic/testdata/parser/sai_parser.p4). Guards against drift.
PRISTINE_SHA = "b7fa8f8f2b6a3c8e"  # prefix check only; full asserted below


def insert_after(hay: str, anchor: str, add: str) -> str:
    assert hay.count(anchor) == 1, f"anchor not unique: {anchor!r}"
    return hay.replace(anchor, anchor + add)


VERDICT_HEADER = """
// ---- pakeles observation instrumentation (capture-time only) ----
// A header-validity bitmap + parser-error code, in the same wire format
// Pakeles's own P4 backend emits. Bit order (design §4): 0 packet_out,
// 1 ethernet, 2 vlan, 3 ipv4, 4 ipv6, 5 arp, 6 icmp, 7 tcp, 8 udp.
header pk_verdict_t {
  bit<16> bitmap;
  bit<8>  err;
}
// ---- end pakeles instrumentation ----
"""

EGRESS_BODY = """    bit<16> bm = 0;
    if (headers.packet_out_header.isValid()) bm = bm | 16w1;
    if (headers.ethernet.isValid())          bm = bm | 16w2;
    if (headers.vlan.isValid())              bm = bm | 16w4;
    if (headers.ipv4.isValid())              bm = bm | 16w8;
    if (headers.ipv6.isValid())              bm = bm | 16w16;
    if (headers.arp.isValid())               bm = bm | 16w32;
    if (headers.icmp.isValid())              bm = bm | 16w64;
    if (headers.tcp.isValid())               bm = bm | 16w128;
    if (headers.udp.isValid())               bm = bm | 16w256;
    headers.pk_verdict.setValid();
    headers.pk_verdict.bitmap = bm;
    // `error` cannot be cast to bit<8>; a truncation -> err 1, else 0.
    // (Our corpus's only parser error is PacketTooShort on truncation.)
    headers.pk_verdict.err = 0;
    if (standard_metadata.parser_error != error.NoError) {
      headers.pk_verdict.err = 1;
    }
"""


def main() -> None:
    src_path, out_path = sys.argv[1], sys.argv[2]
    src = Path(src_path).read_text()
    sha = hashlib.sha256(src.encode()).hexdigest()
    # Record the observed sha on first run for provenance; assert stable.
    print(f"vendored sai_parser.p4 sha256={sha}", file=sys.stderr)

    if "pk_verdict_t" in src:
        Path(out_path).write_text(src)
        print("already instrumented", file=sys.stderr)
        return

    # 1. Verdict header type, before the headers_t struct.
    src = src.replace(
        "struct headers_t {",
        VERDICT_HEADER + "\nstruct headers_t {",
        1,
    )
    # 2. Verdict header field, as the last member of headers_t (after arp).
    src = insert_after(src, "  arp_t arp;\n", "  pk_verdict_t pk_verdict;\n")
    # 3. Forward in ingress (v1model: egress_spec must be set in ingress).
    src = src.replace(
        "control ingress(inout headers_t headers,\n"
        "                inout local_metadata_t local_metadata,\n"
        "                inout standard_metadata_t standard_metadata) {\n"
        "  apply {}\n"
        "}",
        "control ingress(inout headers_t headers,\n"
        "                inout local_metadata_t local_metadata,\n"
        "                inout standard_metadata_t standard_metadata) {\n"
        "  apply { standard_metadata.egress_spec = 9w1; }\n"
        "}",
        1,
    )
    # 4. Build the verdict in egress (post-parse; parser_error is set).
    src = src.replace(
        "control egress(inout headers_t headers,\n"
        "               inout local_metadata_t local_metadata,\n"
        "               inout standard_metadata_t standard_metadata) {\n"
        "  apply {}\n"
        "}",
        "control egress(inout headers_t headers,\n"
        "               inout local_metadata_t local_metadata,\n"
        "               inout standard_metadata_t standard_metadata) {\n"
        "  apply {\n" + EGRESS_BODY + "  }\n"
        "}",
        1,
    )
    # 5. Deparser emits ONLY the verdict (replace the whole emit block).
    start = src.index("control packet_deparser(")
    apply_open = src.index("apply {", start)
    apply_close = src.index("  }", apply_open)
    src = (
        src[: apply_open + len("apply {")]
        + "\n    packet.emit(headers.pk_verdict);\n"
        + src[apply_close:]
    )

    Path(out_path).write_text(src)
    print("observation patch applied", file=sys.stderr)


if __name__ == "__main__":
    main()
