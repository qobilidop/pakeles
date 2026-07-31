//! Flow-dissector differential oracle: our parse (projected to bpf_flow_keys)
//! vs golden flow_keys captured from a flow dissector run in the kernel via
//! BPF_PROG_TEST_RUN. Rung 0: eth/IPv4/IPv6/TCP/UDP subset.
use pakeles::ir::pb;
use serde::{Deserialize, Serialize};

/// The rung-0 subset of `struct bpf_flow_keys`. Addresses are lowercase
/// hex (ipv4 = 8 chars, ipv6 = 32 chars, empty if absent); ports and
/// protocols are host-order integers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct FlowKeys {
    pub nhoff: u16,
    pub thoff: u16,
    pub n_proto: u16,
    pub addr_proto: u16,
    pub ip_proto: u8,
    pub sport: u16,
    pub dport: u16,
    pub ipv4_src: String,
    pub ipv4_dst: String,
    pub ipv6_src: String,
    pub ipv6_dst: String,
    #[serde(default)]
    pub flow_label: u32,
    #[serde(default)]
    pub is_frag: bool,
    #[serde(default)]
    pub is_first_frag: bool,
    #[serde(default)]
    pub is_encap: bool,
}

/// Kernel verdict for a corpus packet: did the flow dissector produce a
/// flow key (`BPF_OK`) or drop (`BPF_DROP`)? v1 goldens predate the field
/// and were all accepts — hence the serde default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    #[default]
    Ok,
    Drop,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenEntry {
    pub packet_hex: String,
    #[serde(default)]
    pub disposition: Disposition,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<FlowKeys>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenFile {
    pub kernel_version: String,
    pub keys_subset: Vec<String>,
    pub entries: Vec<GoldenEntry>,
}

/// Run the interpreter and project an Accept result to `FlowKeys` under the
/// positional-last principle: a field takes its value from the last
/// extraction that would have written it, in parse order — the trace-order
/// analog of upstream bpf_flow.c's overwrite semantics, where each PROG
/// simply overwrites `keys` fields as parsing descends. Two fields are
/// deliberately NOT last-writer: `nhoff` is never advanced past the outer
/// L3 start once VLAN is consumed (bpf_flow.c PROG(IP) :291 advances thoff
/// only), and `n_proto` keeps the outer family even for mixed-family tunnels
/// (bpf_flow.c re-enters parse_eth_proto with a synthetic proto but only
/// PROG(VLAN) rewrites keys->n_proto). `None` if the parse rejects (no flow key).
#[allow(clippy::field_reassign_with_default)]
pub fn project(ir: &pb::Ir, packet: &[u8]) -> anyhow::Result<Option<FlowKeys>> {
    let res = pakeles::interp::run(ir, packet)?;
    if !matches!(res.outcome, pakeles::interp::Outcome::Accept) {
        return Ok(None);
    }
    let field_u = |h: &pakeles::interp::ParsedHeader, f: &str| -> Option<u64> {
        h.fields
            .iter()
            .find(|x| x.name == f)
            .and_then(|x| match &x.value {
                pakeles::interp::FieldValue::Uint(v) => Some(*v),
                _ => None,
            })
    };
    let field_bytes = |h: &pakeles::interp::ParsedHeader, f: &str| -> Option<Vec<u8>> {
        h.fields
            .iter()
            .find(|x| x.name == f)
            .and_then(|x| match &x.value {
                pakeles::interp::FieldValue::Bytes(b) => Some(b.clone()),
                _ => None,
            })
    };

    // One pass in extraction order, tracking the positional writers.
    let mut first_ip: Option<&pakeles::interp::ParsedHeader> = None; // nhoff
    let mut last_ip: Option<&pakeles::interp::ParsedHeader> = None; // addr_proto + addresses
    let mut last_v6: Option<&pakeles::interp::ParsedHeader> = None; // flow_label (only PROG(IPV6) writes it)
    let mut last_next_proto: Option<u64> = None; // ip_proto
    let mut vlans_after_first_ip: u16 = 0; // nhoff (PROG(VLAN) advances it)
    for h in &res.headers {
        match h.instance.as_str() {
            // PROG(VLAN) does keys->nhoff += sizeof(*vlan) per tag,
            // unconditionally — so INNER tags behind TEB (rung 4b) push
            // nhoff past the outer L3 start. Tags before the first IP are
            // already absorbed by "first IP start".
            "vlan_ad" | "vlan_q" => {
                if first_ip.is_some() {
                    vlans_after_first_ip += 1;
                }
            }
            "ipv4" => {
                first_ip.get_or_insert(h);
                last_ip = Some(h);
                // bpf_flow.c PROG(IP): keys->ip_proto = iph->protocol.
                last_next_proto = field_u(h, "protocol");
            }
            "ipv6" => {
                first_ip.get_or_insert(h);
                last_ip = Some(h);
                last_v6 = Some(h);
                // PROG(IPV6): keys->nhoff += sizeof(ip6h); ip_proto via
                // parse_ipv6_proto(ip6h->nexthdr).
                last_next_proto = field_u(h, "next_header");
            }
            // PROG(IPV6OP)/PROG(IPV6FR): each link's own next_header
            // becomes the dispatched proto — last link wins.
            "ext_opt" | "ext_frag" => {
                last_next_proto = field_u(h, "next_header");
            }
            _ => {}
        }
    }

    let mut k = FlowKeys::default();
    // Kernel PROG(VLAN) rewrites n_proto to the tag's encapsulated proto —
    // and PROG(VLAN) runs again for inner tags behind TEB (rung 4b), so
    // the LAST vlan_q wins (the final tag of the innermost stack; an AD
    // tag is always followed by a Q tag). With no VLAN anywhere the first
    // ethernet's type sticks: tunnel re-entry re-enters parse_eth_proto
    // with a synthetic proto, but only PROG(VLAN) touches keys->n_proto.
    k.n_proto = res
        .headers
        .iter()
        .rev()
        .find(|h| h.instance == "vlan_q")
        .and_then(|h| field_u(h, "encapsulated_proto"))
        .or_else(|| {
            res.headers
                .iter()
                .find(|h| h.instance == "ethernet")
                .and_then(|h| field_u(h, "ethertype"))
        })
        .unwrap_or(0) as u16;
    // Declared, not inferred: bpf_flow_keys.is_encap comes from the
    // program's metadata (the metadata-v1 consumer; kernel sets it in
    // parse_ip_proto's IPPROTO_IPIP/IPPROTO_IPV6 arms and, as of rung 4b,
    // after the GRE version-0 optional skip — never on a version!=0 stop).
    k.is_encap = res.metadata.iter().any(|(n, v)| n == "is_encap" && *v != 0);

    // The terminal instance is the last extraction: every accepting state
    // extracts exactly one header (tcp/udp ports, ext_frag stop, mpls
    // stop, gre version!=0 stop).
    let terminal = res
        .headers
        .last()
        .expect("accept implies at least one extraction");

    let Some(first) = first_ip else {
        if terminal.instance == "mpls" {
            // Kernel PROG(MPLS): single-entry read, no key updates — nhoff
            // and thoff stay at the MPLS header start; addr_proto/ports 0.
            k.nhoff = (terminal.start_bit / 8) as u16;
            k.thoff = k.nhoff;
            return Ok(Some(k));
        }
        anyhow::bail!("accept with neither IP nor MPLS instance — unreachable by construction");
    };
    // nhoff: FIRST IP instance — the IP progs never rewrite nhoff on
    // re-entry (they advance thoff instead) — PLUS 4 bytes per VLAN tag
    // parsed after it: PROG(VLAN)'s unconditional nhoff += sizeof(*vlan)
    // also fires for inner tags behind TEB (caught by the rung-4b golden:
    // kernel reports 18, not 14, for TEB + inner 802.1Q).
    k.nhoff = (first.start_bit / 8) as u16 + 4 * vlans_after_first_ip;
    // addr_proto + addresses: LAST IP-family instance, either family —
    // PROG(IP) (bpf_flow.c:291-293) and PROG(IPV6) (:333-334) each
    // overwrite addr_proto and the address union as parsing descends.
    let last = last_ip.expect("first_ip set implies last_ip set");
    if last.instance == "ipv4" {
        k.addr_proto = 0x0800;
        k.ipv4_src = format!("{:08x}", field_u(last, "src").unwrap_or(0));
        k.ipv4_dst = format!("{:08x}", field_u(last, "dst").unwrap_or(0));
    } else {
        k.addr_proto = 0x86DD;
        k.ipv6_src = field_bytes(last, "src").map(hex).unwrap_or_default();
        k.ipv6_dst = field_bytes(last, "dst").map(hex).unwrap_or_default();
    }
    // flow_label: LAST ipv6 instance — only PROG(IPV6) writes it
    // (bpf_flow.c:338), so an inner IPv4 leaves the outer v6 label behind.
    if let Some(v6) = last_v6 {
        k.flow_label = field_u(v6, "flow_label").unwrap_or(0) as u32;
    }
    // ip_proto: the last-extracted next-protocol field overall — the
    // rung-2 "last link wins" ext-chain logic generalized by position.
    // On a GRE stop this is the IP header's 47 that dispatched to GRE.
    k.ip_proto = last_next_proto.unwrap_or(0) as u8;
    match terminal.instance.as_str() {
        // Fragment stop: under default flags a Fragment header is terminal
        // (PROG(IPV6FR) exports BPF_OK); the kernel advances thoff past
        // the 8-byte frag header but never parses L4 ports.
        "ext_frag" => {
            k.is_frag = true;
            k.is_first_frag = field_u(terminal, "frag_off") == Some(0);
            k.thoff = (terminal.start_bit / 8) as u16 + 8;
        }
        // GRE version!=0 stop (rung 4b, kernel IPPROTO_GRE step 2): export
        // BPF_OK with thoff still at the GRE base start — no advance, no
        // is_encap, the optional region never read; ports 0.
        "gre" => {
            k.thoff = (terminal.start_bit / 8) as u16;
        }
        // MPLS behind TEB (rung 4b): PROG(MPLS) read-and-stop as ever —
        // thoff at the MPLS start; the outer IP keys persist positionally.
        "mpls" => {
            k.thoff = (terminal.start_bit / 8) as u16;
        }
        // Innermost L4: ports read at thoff.
        "tcp" | "udp" => {
            k.thoff = (terminal.start_bit / 8) as u16;
            k.sport = field_u(terminal, "sport").unwrap_or(0) as u16;
            k.dport = field_u(terminal, "dport").unwrap_or(0) as u16;
        }
        other => anyhow::bail!("unexpected terminal instance `{other}` on an accept"),
    }
    Ok(Some(k))
}

fn hex(b: Vec<u8>) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Stringify one `keys_subset` field from both `ours` and `golden` for
/// comparison. Unknown field names surface as a guaranteed mismatch rather
/// than silently passing.
fn field_pair(name: &str, ours: &FlowKeys, golden: &FlowKeys) -> (String, String) {
    match name {
        "nhoff" => (ours.nhoff.to_string(), golden.nhoff.to_string()),
        "thoff" => (ours.thoff.to_string(), golden.thoff.to_string()),
        "n_proto" => (ours.n_proto.to_string(), golden.n_proto.to_string()),
        "addr_proto" => (ours.addr_proto.to_string(), golden.addr_proto.to_string()),
        "ip_proto" => (ours.ip_proto.to_string(), golden.ip_proto.to_string()),
        "sport" => (ours.sport.to_string(), golden.sport.to_string()),
        "dport" => (ours.dport.to_string(), golden.dport.to_string()),
        "ipv4_src" => (ours.ipv4_src.clone(), golden.ipv4_src.clone()),
        "ipv4_dst" => (ours.ipv4_dst.clone(), golden.ipv4_dst.clone()),
        "ipv6_src" => (ours.ipv6_src.clone(), golden.ipv6_src.clone()),
        "ipv6_dst" => (ours.ipv6_dst.clone(), golden.ipv6_dst.clone()),
        "flow_label" => (ours.flow_label.to_string(), golden.flow_label.to_string()),
        "is_frag" => (ours.is_frag.to_string(), golden.is_frag.to_string()),
        "is_first_frag" => (
            ours.is_first_frag.to_string(),
            golden.is_first_frag.to_string(),
        ),
        "is_encap" => (ours.is_encap.to_string(), golden.is_encap.to_string()),
        _ => ("<unknown-field>".into(), name.into()),
    }
}

/// The conformance directory holding the committed goldens, shared by the
/// CLI's default `--goldens` resolution and the `committed_goldens_agree`
/// gate test.
/// This example's directory (the crate manifest dir): the description,
/// committed IR, `gen/`, `conformance/`, and `factory/` all live here.
pub fn dir() -> &'static std::path::Path {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// The committed conformance directory (goldens + vector suite).
pub fn conformance_dir() -> std::path::PathBuf {
    dir().join("conformance")
}

/// The example description, parsed from the committed IR (embedded at
/// compile time).
pub fn ir() -> pb::Ir {
    pakeles::ir::from_json(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/linux_flow_dissector.ir.json"
    )))
    .expect("committed linux_flow_dissector IR must parse")
}

/// Find the committed kernel-captured golden file under `dir` (filename
/// starts with `flow_keys.linux-`). Shared by the CLI's default `--goldens`
/// resolution and the `committed_goldens_agree` gate test.
// TODO(rung-2): when multiple kernel-version goldens exist, diff all or
// pick/pin deterministically (find() order is unspecified).
pub fn discover_committed_golden(dir: &std::path::Path) -> Option<std::path::PathBuf> {
    std::fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("flow_keys.linux-"))
        })
}

/// Diff our `project`ed `flow_keys` against a golden file's entries, over
/// the golden's declared `keys_subset` fields.
pub fn diff_goldens(
    ir: &pb::Ir,
    golden: &GoldenFile,
) -> anyhow::Result<pakeles::oracle::GoldenDiffReport> {
    let mut report = pakeles::oracle::GoldenDiffReport {
        compared: 0,
        mismatches: Vec::new(),
    };
    for (i, e) in golden.entries.iter().enumerate() {
        let pkt = pakeles::testvec::hex_decode(&e.packet_hex)?;
        let ours = project(ir, &pkt)?;
        report.compared += 1;
        match (e.disposition, ours) {
            (Disposition::Drop, None) => {} // agree: kernel drops, we reject
            (Disposition::Drop, Some(_)) => report
                .mismatches
                .push(format!("vector {i}: disposition: ours=accept golden=drop")),
            (Disposition::Ok, None) => report
                .mismatches
                .push(format!("vector {i}: disposition: ours=reject golden=ok")),
            (Disposition::Ok, Some(ours)) => {
                let golden_keys = e.keys.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("vector {i}: ok entry without keys — malformed golden")
                })?;
                for field in &golden.keys_subset {
                    let (o, t) = field_pair(field, &ours, golden_keys);
                    if o != t {
                        report
                            .mismatches
                            .push(format!("vector {i}: {field}: ours={o} golden={t}"));
                    }
                }
            }
        }
    }
    Ok(report)
}

/// The example's diff command (`src/main.rs` calls this): the
/// default IR, committed-golden discovery, and the diff. Everything
/// about diffing this incumbent lives in this crate.
pub fn cli_diff(
    ir: Option<&std::path::Path>,
    goldens: Option<&std::path::Path>,
) -> anyhow::Result<pakeles::oracle::GoldenDiffReport> {
    use anyhow::Context as _;
    let ir = match ir {
        None => self::ir(),
        Some(p) => pakeles::ir::load(p)?,
    };
    let goldens = match goldens {
        Some(p) => p.to_path_buf(),
        None => discover_committed_golden(&conformance_dir()).context(
            "no --goldens given and no committed flow_keys.linux-*.golden.json found under linux_flow_dissector/conformance/",
        )?,
    };
    let golden: GoldenFile = serde_json::from_str(
        &std::fs::read_to_string(&goldens)
            .with_context(|| format!("reading goldens from {}", goldens.display()))?,
    )?;
    diff_goldens(&ir, &golden)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn golden_file_roundtrips() {
        let g = GoldenFile {
            kernel_version: "6.8.0".into(),
            keys_subset: vec!["nhoff".into()],
            entries: vec![GoldenEntry {
                packet_hex: "aabb".into(),
                disposition: Disposition::Ok,
                keys: Some(FlowKeys {
                    nhoff: 14,
                    ..Default::default()
                }),
            }],
        };
        let s = serde_json::to_string(&g).unwrap();
        let back: GoldenFile = serde_json::from_str(&s).unwrap();
        assert_eq!(back.entries[0].keys.as_ref().unwrap().nhoff, 14);
        assert_eq!(back.kernel_version, "6.8.0");
    }
}

#[cfg(test)]
mod project_tests {
    use super::*;

    fn hexpkt(s: &str) -> Vec<u8> {
        pakeles::testvec::hex_decode(s).unwrap()
    }

    #[test]
    fn projects_single_vlan_v4_tcp() {
        let ir = ir();
        let pkt = hexpkt(
            "aabbccddeeff112233445566810000640800\
             45000028123440004006dead0a0000010a000002303901bb\
             00000001000000005018ffff00000000",
        );
        let k = project(&ir, &pkt).unwrap().unwrap();
        assert_eq!(k.nhoff, 18); // 14 + one 4-byte tag
        assert_eq!(k.thoff, 38);
        assert_eq!(k.n_proto, 0x0800); // kernel: inner encapsulated proto
        assert_eq!(k.addr_proto, 0x0800);
        assert_eq!(k.ip_proto, 6);
        assert_eq!(k.sport, 12345);
        assert_eq!(k.dport, 443);
    }

    #[test]
    fn projects_qinq_v4_tcp() {
        let ir = ir();
        let pkt = hexpkt(
            "aabbccddeeff11223344556688a80064810000650800\
             45000028123440004006dead0a0000010a000002303901bb\
             00000001000000005018ffff00000000",
        );
        let k = project(&ir, &pkt).unwrap().unwrap();
        assert_eq!(k.nhoff, 22); // 14 + two tags
        assert_eq!(k.thoff, 42);
        assert_eq!(k.n_proto, 0x0800);
        assert_eq!(k.addr_proto, 0x0800);
    }

    #[test]
    fn projects_mpls_stop() {
        let ir = ir();
        let pkt = hexpkt(
            "aabbccddeeff112233445566884700064140\
             45000028123440004006dead0a0000010a000002303901bb\
             00000001000000005018ffff00000000",
        );
        let k = project(&ir, &pkt).unwrap().unwrap();
        assert_eq!(k.nhoff, 14);
        assert_eq!(k.thoff, 14); // kernel PROG(MPLS) leaves thoff untouched
        assert_eq!(k.n_proto, 0x8847);
        assert_eq!(k.addr_proto, 0); // set only by the IP progs upstream
        assert_eq!(k.ip_proto, 0);
        assert_eq!(k.sport, 0);
        assert_eq!(k.dport, 0);
        assert_eq!(k.ipv4_src, "");
        assert_eq!(k.ipv6_src, "");
    }

    #[test]
    fn projects_vlan_then_mpls() {
        let ir = ir();
        let pkt = hexpkt(
            "aabbccddeeff11223344556681000064884700064140\
             45000028123440004006dead0a0000010a000002303901bb\
             00000001000000005018ffff00000000",
        );
        let k = project(&ir, &pkt).unwrap().unwrap();
        assert_eq!(k.nhoff, 18);
        assert_eq!(k.thoff, 18);
        assert_eq!(k.n_proto, 0x8847);
        assert_eq!(k.addr_proto, 0);
    }

    #[test]
    fn triple_tag_rejects() {
        let ir = ir();
        let pkt = hexpkt(
            "aabbccddeeff11223344556688a800648100006581000066\
             080045000028123440004006dead0a0000010a000002303901bb\
             00000001000000005018ffff00000000",
        );
        assert!(project(&ir, &pkt).unwrap().is_none());
    }

    #[test]
    fn projects_v4_tcp_fixture() {
        let ir = ir();
        let pkt = pakeles::fixtures::tcp_packet(); // eth/ipv4/tcp, sport 12345 dport 443
        let k = project(&ir, &pkt).unwrap().unwrap();
        assert_eq!(k.nhoff, 14);
        assert_eq!(k.thoff, 34);
        assert_eq!(k.n_proto, 0x0800);
        assert_eq!(k.ip_proto, 6);
        assert_eq!(k.sport, 12345);
        assert_eq!(k.dport, 443);
        assert_eq!(k.ipv4_src, "0a000001");
        assert_eq!(k.ipv4_dst, "0a000002");
    }

    #[test]
    fn projects_v6_tcp_fixture() {
        let ir = ir();
        let pkt = pakeles::fixtures::ipv6_tcp_packet(); // eth/ipv6/tcp
        let k = project(&ir, &pkt).unwrap().unwrap();
        assert_eq!(k.nhoff, 14);
        assert_eq!(k.thoff, 54);
        assert_eq!(k.n_proto, 0x86dd);
        assert_eq!(k.ip_proto, 6);
        assert_eq!(k.sport, 12345);
        assert_eq!(k.dport, 443);
        assert_eq!(k.ipv6_src, "20010db8000000000000000000000001");
        assert_eq!(k.ipv6_dst, "20010db8000000000000000000000002");
        assert_eq!(k.ipv4_src, "");
        assert_eq!(k.ipv4_dst, "");
    }

    #[test]
    fn projects_v4_udp_fixture() {
        let ir = ir();
        let pkt = pakeles::fixtures::udp_packet(); // eth/ipv4/udp, sport 12345 dport 443
        let k = project(&ir, &pkt).unwrap().unwrap();
        assert_eq!(k.nhoff, 14);
        assert_eq!(k.thoff, 34);
        assert_eq!(k.n_proto, 0x0800);
        assert_eq!(k.ip_proto, 17);
        assert_eq!(k.sport, 12345);
        assert_eq!(k.dport, 443);
        assert_eq!(k.ipv4_src, "0a000001");
        assert_eq!(k.ipv4_dst, "0a000002");
    }

    // ---- rung 2: IPv6 extension-header chain ------------------------------
    // Each accept packet's hex below is the byte-identical twin of the
    // Task-5 corpus line (Task 5 replays these exact hexes against the real
    // kernel). Layout: eth=14 (ethertype 0x86dd), IPv6=40 (4-byte
    // version/tc/flow_label, 2-byte payload_length, 1-byte next_header,
    // 1-byte hop_limit, 16-byte src, 16-byte dst), IPv6ExtOpt=8 (hdr_ext_len=0
    // => 6-byte body), IPv6Frag=8, TCP=20, UDP=8. nhoff=14 (ipv6 at off 14).

    #[test]
    fn projects_ipv6_hopopt_tcp() {
        // eth/IPv6(nexthdr=0 HopByHop)/HopByHop(hdr_ext_len=0, nexthdr=6)/TCP
        // ipv6: 60000000 | plen=001c(28=8+20) | nh=00 | hlim=40 | src | dst
        // hopopt: nh=06 hel=00 body=000000000000  (8 bytes)
        let ir = ir();
        let pkt = hexpkt(
            "aabbccddeeff11223344556686dd\
             60000000001c0040\
             20010db8000000000000000000000001\
             20010db8000000000000000000000002\
             0600000000000000\
             303901bb00000001000000005018ffff00000000",
        );
        let k = project(&ir, &pkt).unwrap().unwrap();
        assert_eq!(k.n_proto, 0x86dd);
        assert_eq!(k.addr_proto, 0x86dd);
        assert_eq!(k.nhoff, 14);
        assert_eq!(k.ip_proto, 6); // terminal L4 proto = last link's next_header
        assert_eq!(k.thoff, 62); // 14 + 40 (ipv6) + 8 (one option) = TCP start
        assert!(!k.is_frag);
        assert_eq!(k.sport, 12345);
        assert_eq!(k.dport, 443);
        assert_eq!(k.ipv6_src, "20010db8000000000000000000000001");
        assert_eq!(k.ipv6_dst, "20010db8000000000000000000000002");
    }

    #[test]
    fn projects_ipv6_frag_first() {
        // eth/IPv6(nexthdr=44 Fragment)/Fragment(frag_off=0, nexthdr=6) — stops
        // ipv6: 60000000 | plen=0008 | nh=2c | hlim=40 | src | dst
        // frag: nh=06 res=00 [frag_off=0/res2=0/m=0 => 0000] id=00000001
        let ir = ir();
        let pkt = hexpkt(
            "aabbccddeeff11223344556686dd\
             6000000000082c40\
             20010db8000000000000000000000001\
             20010db8000000000000000000000002\
             0600000000000001",
        );
        let k = project(&ir, &pkt).unwrap().unwrap();
        assert_eq!(k.n_proto, 0x86dd);
        assert_eq!(k.addr_proto, 0x86dd);
        assert_eq!(k.nhoff, 14);
        assert!(k.is_frag);
        assert!(k.is_first_frag);
        assert_eq!(k.ip_proto, 6); // fragment header's next_header
        assert_eq!(k.thoff, 62); // 14 + 40 + 8 (frag header), ports unparsed
        assert_eq!(k.sport, 0);
        assert_eq!(k.dport, 0);
    }

    #[test]
    fn projects_ipv6_frag_later() {
        // eth/IPv6(nexthdr=44)/Fragment(frag_off=1, m_flag=1) — non-first frag.
        // frag 2-byte offset field = (frag_off<<3)|(res2<<1)|m = (1<<3)|1 = 0x0009
        let ir = ir();
        let pkt = hexpkt(
            "aabbccddeeff11223344556686dd\
             6000000000082c40\
             20010db8000000000000000000000001\
             20010db8000000000000000000000002\
             0600000900000001",
        );
        let k = project(&ir, &pkt).unwrap().unwrap();
        assert!(k.is_frag);
        assert!(!k.is_first_frag); // frag_off != 0
        assert_eq!(k.ip_proto, 6);
        assert_eq!(k.thoff, 62);
        assert_eq!(k.sport, 0);
        assert_eq!(k.dport, 0);
    }

    #[test]
    fn projects_ipv6_two_opts_udp() {
        // eth/IPv6(nexthdr=0x3c DestOpts)/DestOpts(nexthdr=0x00 HopByHop)/
        //   HopByHop(nexthdr=17 UDP)/UDP — proves ip_proto reads the LAST link.
        // ipv6: 60000000 | plen=0018(24=8+8+8) | nh=3c | hlim=40 | src | dst
        // destopts: nh=00 hel=00 body=6*00      (8 bytes)
        // hopopt:   nh=11 hel=00 body=6*00      (8 bytes)  (0x11 = 17)
        // udp:      sport=3039 dport=01bb len=0008 csum=0000
        let ir = ir();
        let pkt = hexpkt(
            "aabbccddeeff11223344556686dd\
             6000000000183c40\
             20010db8000000000000000000000001\
             20010db8000000000000000000000002\
             0000000000000000\
             1100000000000000\
             303901bb00080000",
        );
        let k = project(&ir, &pkt).unwrap().unwrap();
        assert_eq!(k.n_proto, 0x86dd);
        assert_eq!(k.addr_proto, 0x86dd);
        assert_eq!(k.nhoff, 14);
        assert_eq!(k.ip_proto, 17); // LAST link (HopByHop.next_header), NOT 0
        assert_eq!(k.thoff, 70); // 14 + 40 + 8 + 8 = UDP start
        assert!(!k.is_frag);
        assert_eq!(k.sport, 12345);
        assert_eq!(k.dport, 443);
    }

    #[test]
    fn projects_ipv6_flow_label() {
        // eth/IPv6(flow_label=0x12345, nexthdr=6)/TCP — flow_label recorded,
        // no early stop under default flags.
        // ver/tc/fl word: version=6, tc=0, flow_label=0x12345 => 0x60012345
        let ir = ir();
        let pkt = hexpkt(
            "aabbccddeeff11223344556686dd\
             6001234500140640\
             20010db8000000000000000000000001\
             20010db8000000000000000000000002\
             303901bb00000001000000005018ffff00000000",
        );
        let k = project(&ir, &pkt).unwrap().unwrap();
        assert_eq!(k.flow_label, 0x12345); // 74565
        assert_eq!(k.ip_proto, 6);
        assert_eq!(k.thoff, 54); // 14 + 40, no options
        assert!(!k.is_frag);
        assert_eq!(k.sport, 12345);
        assert_eq!(k.dport, 443);
    }

    // ---- rung 4a: IPIP / IPv6-in-IP tunnel re-entrancy --------------------
    // Each accept packet's hex below is the byte-identical twin of its
    // rung-4a corpus line (the corpus replays these exact hexes against the
    // real kernel). V4SRC/V4DST inner = c0a80001/c0a80002; outer v4 =
    // 0a000001/0a000002; v6 outer pair ..0001/..0002, inner pair ..0003/..0004.

    #[test]
    fn projects_ipip_v4_in_v4() {
        // eth/IPv4(proto=4)/IPv4(proto=6)/TCP — inner addresses win.
        let ir = ir();
        let pkt = hexpkt(
            "aabbccddeeff1122334455660800\
             4500003c123440004004dead0a0000010a000002\
             45000028123440004006deadc0a80001c0a80002\
             303901bb00000001000000005018ffff00000000",
        );
        let k = project(&ir, &pkt).unwrap().unwrap();
        assert!(k.is_encap);
        assert_eq!(k.nhoff, 14); // OUTER L3 start — kernel never rewrites it
        assert_eq!(k.thoff, 54); // 14 + 20 + 20
        assert_eq!(k.n_proto, 0x0800);
        assert_eq!(k.addr_proto, 0x0800);
        assert_eq!(k.ip_proto, 6); // inner protocol, not 4
        assert_eq!(k.ipv4_src, "c0a80001"); // INNER wins (bpf_flow.c:292-293)
        assert_eq!(k.ipv4_dst, "c0a80002");
        assert_eq!(k.sport, 12345);
        assert_eq!(k.dport, 443);
    }

    #[test]
    fn projects_ip6ip_v6_in_v4() {
        // eth/IPv4(proto=41)/IPv6(nh=6)/TCP — mixed family: n_proto stays
        // the OUTER family, addr_proto flips to the inner one.
        let ir = ir();
        let pkt = hexpkt(
            "aabbccddeeff1122334455660800\
             45000050123440004029dead0a0000010a000002\
             6000000000140640\
             20010db8000000000000000000000001\
             20010db8000000000000000000000002\
             303901bb00000001000000005018ffff00000000",
        );
        let k = project(&ir, &pkt).unwrap().unwrap();
        assert!(k.is_encap);
        assert_eq!(k.nhoff, 14);
        assert_eq!(k.thoff, 74); // 14 + 20 + 40
        assert_eq!(k.n_proto, 0x0800); // outer family sticks
        assert_eq!(k.addr_proto, 0x86DD); // inner family
        assert_eq!(k.ip_proto, 6);
        assert_eq!(k.ipv6_src, "20010db8000000000000000000000001");
        assert_eq!(k.ipv6_dst, "20010db8000000000000000000000002");
        assert_eq!(k.ipv4_src, ""); // v4 union bytes never printed for v6
        assert_eq!(k.sport, 12345);
        assert_eq!(k.dport, 443);
    }

    #[test]
    fn projects_ipip_v4_in_v6_keeps_outer_flow_label() {
        // eth/IPv6(fl=0x12345, nh=4)/IPv4(proto=17)/UDP — the inner v4
        // overwrites the address union but NOT flow_label (only PROG(IPV6)
        // writes it, bpf_flow.c:338).
        let ir = ir();
        let pkt = hexpkt(
            "aabbccddeeff11223344556686dd\
             60012345001c0440\
             20010db8000000000000000000000001\
             20010db8000000000000000000000002\
             4500001c123440004011deadc0a80001c0a80002\
             303901bb00080000",
        );
        let k = project(&ir, &pkt).unwrap().unwrap();
        assert!(k.is_encap);
        assert_eq!(k.nhoff, 14);
        assert_eq!(k.thoff, 74); // 14 + 40 + 20
        assert_eq!(k.n_proto, 0x86DD); // outer
        assert_eq!(k.addr_proto, 0x0800); // inner
        assert_eq!(k.flow_label, 0x12345); // OUTER v6's label survives
        assert_eq!(k.ip_proto, 17);
        assert_eq!(k.ipv4_src, "c0a80001");
        assert_eq!(k.ipv6_src, "");
        assert_eq!(k.sport, 12345);
        assert_eq!(k.dport, 443);
    }

    #[test]
    fn projects_ip6ip_v6_in_v6_inner_wins() {
        // eth/IPv6(fl=0x11111, nh=41, ..0001/..0002)/IPv6(fl=0x22222,
        // nh=17, ..0003/..0004)/UDP — inner label AND inner addresses win.
        let ir = ir();
        let pkt = hexpkt(
            "aabbccddeeff11223344556686dd\
             6001111100302940\
             20010db8000000000000000000000001\
             20010db8000000000000000000000002\
             6002222200081140\
             20010db8000000000000000000000003\
             20010db8000000000000000000000004\
             303901bb00080000",
        );
        let k = project(&ir, &pkt).unwrap().unwrap();
        assert!(k.is_encap);
        assert_eq!(k.thoff, 94); // 14 + 40 + 40
        assert_eq!(k.addr_proto, 0x86DD);
        assert_eq!(k.flow_label, 0x22222); // inner
        assert_eq!(k.ipv6_src, "20010db8000000000000000000000003");
        assert_eq!(k.ipv6_dst, "20010db8000000000000000000000004");
        assert_eq!(k.ip_proto, 17);
    }

    #[test]
    fn projects_double_encap_innermost_wins() {
        // eth/IPv4(p=4, 0a..)/IPv4(p=4, ac10..)/IPv4(p=6, c0a8..)/TCP —
        // three stacked ipv4 instances; the innermost writes last.
        let ir = ir();
        let pkt = hexpkt(
            "aabbccddeeff1122334455660800\
             45000050123440004004dead0a0000010a000002\
             4500003c123440004004deadac100001ac100002\
             45000028123440004006deadc0a80001c0a80002\
             303901bb00000001000000005018ffff00000000",
        );
        let k = project(&ir, &pkt).unwrap().unwrap();
        assert!(k.is_encap);
        assert_eq!(k.nhoff, 14);
        assert_eq!(k.thoff, 74); // 14 + 20*3
        assert_eq!(k.ipv4_src, "c0a80001");
        assert_eq!(k.ipv4_dst, "c0a80002");
        assert_eq!(k.ip_proto, 6);
    }

    #[test]
    fn projects_tunnel_behind_ext_chain() {
        // eth/IPv6(nh=0)/HopByHop(nh=4)/IPv4/TCP — the chain's LAST link
        // carries the tunnel proto; re-entry from parse_ipv6_opt.
        let ir = ir();
        let pkt = hexpkt(
            "aabbccddeeff11223344556686dd\
             6000000000300040\
             20010db8000000000000000000000001\
             20010db8000000000000000000000002\
             0400000000000000\
             45000028123440004006deadc0a80001c0a80002\
             303901bb00000001000000005018ffff00000000",
        );
        let k = project(&ir, &pkt).unwrap().unwrap();
        assert!(k.is_encap);
        assert_eq!(k.nhoff, 14);
        assert_eq!(k.thoff, 82); // 14 + 40 + 8 + 20
        assert_eq!(k.addr_proto, 0x0800);
        assert_eq!(k.ipv4_src, "c0a80001");
        assert_eq!(k.ip_proto, 6);
        assert_eq!(k.sport, 12345);
    }

    #[test]
    fn projects_tunnel_behind_qinq() {
        // eth/AD/Q/IPv4(p=4)/IPv4/TCP — nhoff stays at the OUTER L3 start
        // past both tags; n_proto from the final tag.
        let ir = ir();
        let pkt = hexpkt(
            "aabbccddeeff11223344556688a80064810000650800\
             4500003c123440004004dead0a0000010a000002\
             45000028123440004006deadc0a80001c0a80002\
             303901bb00000001000000005018ffff00000000",
        );
        let k = project(&ir, &pkt).unwrap().unwrap();
        assert!(k.is_encap);
        assert_eq!(k.nhoff, 22); // 14 + two 4-byte tags
        assert_eq!(k.thoff, 62); // 22 + 20 + 20
        assert_eq!(k.n_proto, 0x0800);
        assert_eq!(k.ipv4_src, "c0a80001");
    }

    #[test]
    fn projects_fragmented_outer_stops_before_reentry() {
        // eth/IPv6(nh=44)/Frag(nh=41, off=0) — the fragment is terminal
        // under default flags: the tunnel arm is never reached, so
        // is_encap stays FALSE while ip_proto records 41.
        let ir = ir();
        let pkt = hexpkt(
            "aabbccddeeff11223344556686dd\
             6000000000082c40\
             20010db8000000000000000000000001\
             20010db8000000000000000000000002\
             2900000000000001",
        );
        let k = project(&ir, &pkt).unwrap().unwrap();
        assert!(!k.is_encap); // frag stopped before the encap arm
        assert!(k.is_frag);
        assert!(k.is_first_frag);
        assert_eq!(k.ip_proto, 41);
        assert_eq!(k.thoff, 62); // 14 + 40 + 8
        assert_eq!(k.addr_proto, 0x86DD);
        assert_eq!(k.sport, 0);
        assert_eq!(k.dport, 0);
    }

    #[test]
    fn projects_fragmented_inner() {
        // eth/IPv4(p=41)/IPv6(nh=44)/Frag(nh=6) — encap happened, THEN the
        // inner fragment stopped: is_encap AND is_frag.
        let ir = ir();
        let pkt = hexpkt(
            "aabbccddeeff1122334455660800\
             45000044123440004029dead0a0000010a000002\
             6000000000082c40\
             20010db8000000000000000000000001\
             20010db8000000000000000000000002\
             0600000000000001",
        );
        let k = project(&ir, &pkt).unwrap().unwrap();
        assert!(k.is_encap);
        assert!(k.is_frag);
        assert!(k.is_first_frag);
        assert_eq!(k.nhoff, 14);
        assert_eq!(k.thoff, 82); // 14 + 20 + 40 + 8
        assert_eq!(k.addr_proto, 0x86DD);
        assert_eq!(k.ip_proto, 6);
        assert_eq!(k.sport, 0);
    }

    #[test]
    fn projects_inner_ext_chain() {
        // eth/IPv4(p=41)/IPv6(nh=0)/HopByHop(nh=6)/TCP — ext-chain walk
        // inside the tunnel.
        let ir = ir();
        let pkt = hexpkt(
            "aabbccddeeff1122334455660800\
             45000058123440004029dead0a0000010a000002\
             60000000001c0040\
             20010db8000000000000000000000001\
             20010db8000000000000000000000002\
             0600000000000000\
             303901bb00000001000000005018ffff00000000",
        );
        let k = project(&ir, &pkt).unwrap().unwrap();
        assert!(k.is_encap);
        assert_eq!(k.nhoff, 14);
        assert_eq!(k.thoff, 82); // 14 + 20 + 40 + 8
        assert_eq!(k.n_proto, 0x0800);
        assert_eq!(k.addr_proto, 0x86DD);
        assert_eq!(k.ip_proto, 6);
        assert_eq!(k.sport, 12345);
        assert_eq!(k.dport, 443);
    }

    #[test]
    fn non_tunnel_parses_report_no_encap() {
        // Regression guard: the plain fixture path never sets is_encap.
        let ir = ir();
        let k = project(&ir, &pakeles::fixtures::tcp_packet())
            .unwrap()
            .unwrap();
        assert!(!k.is_encap);
    }

    // ---- rung 4b: GRE ----------------------------------------------------
    // Each hex below is the byte-identical twin of a rung-4b corpus line.
    // GRE base = 4 bytes {flags+version, proto}; C/K/S each add 4 optional
    // bytes. Layout constants: eth=14, IPv4=20 (ihl=5), IPv6=40, GRE=4.

    #[test]
    fn projects_gre_v4_tcp() {
        // eth/IPv4(p=47)/GRE(v0, no flags, proto=0x0800)/IPv4/TCP
        let ir = ir();
        let pkt = hexpkt(
            "aabbccddeeff1122334455660800\
             4500004012344000402fdead0a0000010a000002\
             00000800\
             45000028123440004006deadc0a80001c0a80002\
             303901bb00000001000000005018ffff00000000",
        );
        let k = project(&ir, &pkt).unwrap().unwrap();
        assert!(k.is_encap); // set by parse_gre_opt (version 0)
        assert_eq!(k.nhoff, 14);
        assert_eq!(k.thoff, 58); // 14 + 20 + 4 (gre, no optionals) + 20
        assert_eq!(k.n_proto, 0x0800);
        assert_eq!(k.addr_proto, 0x0800);
        assert_eq!(k.ip_proto, 6);
        assert_eq!(k.sport, 12345);
        assert_eq!(k.dport, 443);
        assert_eq!(k.ipv4_src, "c0a80001"); // inner
        assert_eq!(k.ipv4_dst, "c0a80002");
    }

    #[test]
    fn projects_gre_v6_udp() {
        // eth/IPv6(nh=47)/GRE(v0, proto=0x86DD)/IPv6/UDP — inner v6 wins
        // addresses AND flow_label (0x12345).
        let ir = ir();
        let pkt = hexpkt(
            "aabbccddeeff11223344556686dd\
             6000000000342f40\
             20010db8000000000000000000000001\
             20010db8000000000000000000000002\
             000086dd\
             6001234500081140\
             20010db8000000000000000000000003\
             20010db8000000000000000000000004\
             303901bb00080000",
        );
        let k = project(&ir, &pkt).unwrap().unwrap();
        assert!(k.is_encap);
        assert_eq!(k.nhoff, 14);
        assert_eq!(k.thoff, 98); // 14 + 40 + 4 + 40
        assert_eq!(k.n_proto, 0x86DD);
        assert_eq!(k.addr_proto, 0x86DD);
        assert_eq!(k.ip_proto, 17);
        assert_eq!(k.flow_label, 0x12345); // inner v6 label
        assert_eq!(k.ipv6_src, "20010db8000000000000000000000003");
        assert_eq!(k.ipv6_dst, "20010db8000000000000000000000004");
        assert_eq!(k.sport, 12345);
        assert_eq!(k.dport, 443);
    }

    #[test]
    fn projects_gre_csum() {
        // GRE with C set: 4 bytes of checksum+pad before the inner IPv4.
        let ir = ir();
        let pkt = hexpkt(
            "aabbccddeeff1122334455660800\
             4500004412344000402fdead0a0000010a000002\
             80000800\
             00000000\
             45000028123440004006deadc0a80001c0a80002\
             303901bb00000001000000005018ffff00000000",
        );
        let k = project(&ir, &pkt).unwrap().unwrap();
        assert!(k.is_encap);
        assert_eq!(k.thoff, 62); // 14 + 20 + 4 + 4 + 20
        assert_eq!(k.ip_proto, 6);
        assert_eq!(k.ipv4_src, "c0a80001");
    }

    #[test]
    fn projects_gre_key_seq() {
        // GRE with K+S set: 8 optional bytes.
        let ir = ir();
        let pkt = hexpkt(
            "aabbccddeeff1122334455660800\
             4500004812344000402fdead0a0000010a000002\
             30000800\
             0000000100000002\
             45000028123440004006deadc0a80001c0a80002\
             303901bb00000001000000005018ffff00000000",
        );
        let k = project(&ir, &pkt).unwrap().unwrap();
        assert!(k.is_encap);
        assert_eq!(k.thoff, 66); // 14 + 20 + 4 + 8 + 20
        assert_eq!(k.sport, 12345);
    }

    #[test]
    fn projects_gre_all_flags() {
        // GRE with C+K+S set: 12 optional bytes.
        let ir = ir();
        let pkt = hexpkt(
            "aabbccddeeff1122334455660800\
             4500004c12344000402fdead0a0000010a000002\
             b0000800\
             000000000000000100000002\
             45000028123440004006deadc0a80001c0a80002\
             303901bb00000001000000005018ffff00000000",
        );
        let k = project(&ir, &pkt).unwrap().unwrap();
        assert!(k.is_encap);
        assert_eq!(k.thoff, 70); // 14 + 20 + 4 + 12 + 20
        assert_eq!(k.dport, 443);
    }

    #[test]
    fn projects_gre_version1_stop() {
        // version=1 with C/K/S set and a TRUNCATED tail: kernel step-2
        // ordering — version!=0 exports BPF_OK before the optional region
        // is ever read, so the missing optionals are invisible. thoff
        // stays at the GRE base start; no is_encap; ports 0.
        let ir = ir();
        let pkt = hexpkt(
            "aabbccddeeff1122334455660800\
             4500001812344000402fdead0a0000010a000002\
             b0010800",
        );
        let k = project(&ir, &pkt).unwrap().unwrap();
        assert!(!k.is_encap); // never assigned on the version!=0 stop
        assert!(!k.is_frag);
        assert_eq!(k.nhoff, 14);
        assert_eq!(k.thoff, 34); // GRE base start — not advanced
        assert_eq!(k.n_proto, 0x0800);
        assert_eq!(k.addr_proto, 0x0800); // outer (only) IP layer
        assert_eq!(k.ipv4_src, "0a000001");
        assert_eq!(k.ip_proto, 47); // positional-last: outer protocol
        assert_eq!(k.sport, 0);
        assert_eq!(k.dport, 0);
    }

    #[test]
    fn projects_gre_teb() {
        // TEB (0x6558): inner Ethernet re-enters the top dispatcher.
        let ir = ir();
        let pkt = hexpkt(
            "aabbccddeeff1122334455660800\
             4500004e12344000402fdead0a0000010a000002\
             00006558\
             b1b2b3b4b5b6c1c2c3c4c5c60800\
             45000028123440004006deadc0a80001c0a80002\
             303901bb00000001000000005018ffff00000000",
        );
        let k = project(&ir, &pkt).unwrap().unwrap();
        assert!(k.is_encap);
        assert_eq!(k.nhoff, 14); // outer L3, not the inner one
        assert_eq!(k.thoff, 72); // 14 + 20 + 4 + 14 + 20
        assert_eq!(k.n_proto, 0x0800); // no VLAN: first ethernet sticks
        assert_eq!(k.addr_proto, 0x0800);
        assert_eq!(k.ipv4_src, "c0a80001");
        assert_eq!(k.ip_proto, 6);
        assert_eq!(k.sport, 12345);
    }

    #[test]
    fn projects_gre_teb_inner_vlan_rewrites_n_proto() {
        // TEB + inner 802.1Q carrying IPv6: kernel PROG(VLAN) runs for the
        // INNER tag too, so n_proto = the inner tag's encapsulated proto
        // (0x86DD) even though the outer family is IPv4 — the rule that
        // makes n_proto "LAST vlan_q", not "first".
        let ir = ir();
        let pkt = hexpkt(
            "aabbccddeeff1122334455660800\
             4500006612344000402fdead0a0000010a000002\
             00006558\
             b1b2b3b4b5b6c1c2c3c4c5c68100\
             006586dd\
             6001234500140640\
             20010db8000000000000000000000003\
             20010db8000000000000000000000004\
             303901bb00000001000000005018ffff00000000",
        );
        let k = project(&ir, &pkt).unwrap().unwrap();
        assert!(k.is_encap);
        // PROG(VLAN) advances nhoff for the INNER tag too: 14 (outer L3) + 4.
        assert_eq!(k.nhoff, 18);
        assert_eq!(k.thoff, 96); // 14 + 20 + 4 + 14 + 4 + 40
        assert_eq!(k.n_proto, 0x86DD); // inner tag's encapsulated proto
        assert_eq!(k.addr_proto, 0x86DD);
        assert_eq!(k.flow_label, 0x12345);
        assert_eq!(k.ipv6_src, "20010db8000000000000000000000003");
        assert_eq!(k.ip_proto, 6);
        assert_eq!(k.sport, 12345);
    }

    #[test]
    fn projects_gre_behind_ipip() {
        // Mixed-arm double encap: eth/IPv4(p=4)/IPv4(p=47)/GRE/IPv4/TCP.
        let ir = ir();
        let pkt = hexpkt(
            "aabbccddeeff1122334455660800\
             45000054123440004004dead0a0000010a000002\
             4500004012344000402fdead0a0000030a000004\
             00000800\
             45000028123440004006deadc0a80001c0a80002\
             303901bb00000001000000005018ffff00000000",
        );
        let k = project(&ir, &pkt).unwrap().unwrap();
        assert!(k.is_encap);
        assert_eq!(k.nhoff, 14); // FIRST IP
        assert_eq!(k.thoff, 78); // 14 + 20 + 20 + 4 + 20
        assert_eq!(k.addr_proto, 0x0800);
        assert_eq!(k.ipv4_src, "c0a80001"); // innermost
        assert_eq!(k.ip_proto, 6);
        assert_eq!(k.dport, 443);
    }

    #[test]
    fn projects_gre_mpls_over_teb() {
        // TEB + inner Ethernet carrying MPLS: PROG(MPLS) read-and-stop —
        // thoff at the MPLS start, outer IP keys persist, ip_proto stays
        // 47 (the outer protocol that dispatched to GRE), ports 0.
        let ir = ir();
        let pkt = hexpkt(
            "aabbccddeeff1122334455660800\
             4500002a12344000402fdead0a0000010a000002\
             00006558\
             b1b2b3b4b5b6c1c2c3c4c5c68847\
             00064140",
        );
        let k = project(&ir, &pkt).unwrap().unwrap();
        assert!(k.is_encap);
        assert_eq!(k.nhoff, 14);
        assert_eq!(k.thoff, 52); // MPLS start: 14 + 20 + 4 + 14
        assert_eq!(k.n_proto, 0x0800); // no VLAN anywhere
        assert_eq!(k.addr_proto, 0x0800); // outer IP layer
        assert_eq!(k.ipv4_src, "0a000001");
        assert_eq!(k.ip_proto, 47);
        assert_eq!(k.sport, 0);
        assert_eq!(k.dport, 0);
    }

    #[test]
    fn gre_truncated_base_rejects() {
        // Only 2 of the 4 GRE base bytes present: header read fails, DROP.
        let ir = ir();
        let pkt = hexpkt(
            "aabbccddeeff1122334455660800\
             4500001812344000402fdead0a0000010a000002\
             0000",
        );
        assert!(project(&ir, &pkt).unwrap().is_none());
    }

    #[test]
    fn gre_truncated_inner_after_optionals_rejects() {
        // version 0, C set, optionals present, inner IPv4 truncated: the
        // kernel's optionals are thoff arithmetic (not reads) — the drop
        // comes from the INNER header read failing.
        let ir = ir();
        let pkt = hexpkt(
            "aabbccddeeff1122334455660800\
             4500002612344000402fdead0a0000010a000002\
             80000800\
             00000000\
             45000028123440004006",
        );
        assert!(project(&ir, &pkt).unwrap().is_none());
    }

    #[test]
    fn gre_teb_truncated_inner_eth_rejects() {
        // TEB with only 8 of the 14 inner Ethernet bytes: DROP both sides.
        let ir = ir();
        let pkt = hexpkt(
            "aabbccddeeff1122334455660800\
             4500002012344000402fdead0a0000010a000002\
             00006558\
             b1b2b3b4b5b6c1c2",
        );
        assert!(project(&ir, &pkt).unwrap().is_none());
    }

    #[test]
    fn gre_arp_rejects() {
        // ARP-over-GRE: proto 0x0806 hits the dispatcher default, DROP.
        let ir = ir();
        let pkt = hexpkt(
            "aabbccddeeff1122334455660800\
             4500003412344000402fdead0a0000010a000002\
             00000806\
             0001080006040001aabbccddeeff0a000001112233445566\
             0a000002",
        );
        assert!(project(&ir, &pkt).unwrap().is_none());
    }
}

#[cfg(test)]
mod diff_tests {
    use super::*;
    fn golden_from_fixture() -> GoldenFile {
        let ir = ir();
        let pkt = pakeles::fixtures::tcp_packet();
        let keys = super::project(&ir, &pkt).unwrap().unwrap();
        GoldenFile {
            kernel_version: "test".into(),
            keys_subset: vec![
                "nhoff".into(),
                "thoff".into(),
                "sport".into(),
                "dport".into(),
            ],
            entries: vec![GoldenEntry {
                packet_hex: pkt.iter().map(|b| format!("{b:02x}")).collect(),
                disposition: Disposition::Ok,
                keys: Some(keys),
            }],
        }
    }
    #[test]
    fn diff_green_on_self() {
        let ir = ir();
        let report = diff_goldens(&ir, &golden_from_fixture()).unwrap();
        assert_eq!(report.compared, 1);
        assert!(report.mismatches.is_empty(), "{:#?}", report.mismatches);
    }
    #[test]
    fn diff_catches_mismatch() {
        let ir = ir();
        let mut g = golden_from_fixture();
        g.entries[0].keys.as_mut().unwrap().dport = 1; // corrupt
        let report = diff_goldens(&ir, &g).unwrap();
        assert_eq!(report.mismatches.len(), 1);
    }
    #[test]
    fn drop_entry_agrees_when_we_reject() {
        // ARP ethertype: kernel drops, our parse rejects — agreement.
        let ir = ir();
        let mut g = golden_from_fixture();
        g.entries[0].packet_hex = "aabbccddeeff1122334455660806000108000604000111223344\
             55660a000001aabbccddeeff0a000002"
            .into();
        g.entries[0].disposition = Disposition::Drop;
        g.entries[0].keys = None;
        let report = diff_goldens(&ir, &g).unwrap();
        assert_eq!(report.compared, 1);
        assert!(report.mismatches.is_empty(), "{:#?}", report.mismatches);
    }
    #[test]
    fn drop_entry_mismatches_when_we_accept() {
        // Kernel claims drop on a packet we accept -> disagreement.
        let ir = ir();
        let mut g = golden_from_fixture();
        g.entries[0].disposition = Disposition::Drop;
        g.entries[0].keys = None;
        let report = diff_goldens(&ir, &g).unwrap();
        assert_eq!(report.mismatches.len(), 1);
        assert!(report.mismatches[0].contains("disposition"));
    }
    #[test]
    fn ok_entry_mismatches_when_we_reject() {
        let ir = ir();
        let mut g = golden_from_fixture();
        g.entries[0].packet_hex = "aabbcc".into(); // truncated -> we reject
        let report = diff_goldens(&ir, &g).unwrap();
        assert_eq!(report.mismatches.len(), 1);
        assert!(report.mismatches[0].contains("disposition"));
    }
    #[test]
    fn v2_golden_without_v3_fields_still_parses() {
        // A v2 "ok" entry lacking flow_label/is_frag/is_first_frag must
        // deserialize with those fields defaulted (0 / false).
        let s = r#"{"kernel_version":"6.8.0","keys_subset":["nhoff"],
            "entries":[{"packet_hex":"aabb","disposition":"ok","keys":{"nhoff":14,
            "thoff":0,"n_proto":0,"addr_proto":0,"ip_proto":0,"sport":0,"dport":0,
            "ipv4_src":"","ipv4_dst":"","ipv6_src":"","ipv6_dst":""}}]}"#;
        let g: GoldenFile = serde_json::from_str(s).unwrap();
        let k = g.entries[0].keys.as_ref().unwrap();
        assert_eq!(k.flow_label, 0);
        assert!(!k.is_frag);
        assert!(!k.is_first_frag);
    }
    #[test]
    fn v1_golden_without_disposition_still_parses() {
        let s = r#"{"kernel_version":"6.8.0","keys_subset":["nhoff"],
            "entries":[{"packet_hex":"aabb","keys":{"nhoff":14,"thoff":0,
            "n_proto":0,"addr_proto":0,"ip_proto":0,"sport":0,"dport":0,
            "ipv4_src":"","ipv4_dst":"","ipv6_src":"","ipv6_dst":""}}]}"#;
        let g: GoldenFile = serde_json::from_str(s).unwrap();
        assert_eq!(g.entries[0].disposition, Disposition::Ok);
        assert_eq!(g.entries[0].keys.as_ref().unwrap().nhoff, 14);
    }
}

#[cfg(test)]
mod gate_tests {
    use super::*;

    /// The --goldens override path (what the factories' replay scripts
    /// use): a runtime-minted golden diffs clean.
    #[test]
    fn cli_diff_accepts_goldens_override() {
        let ir = ir();
        let pkt = pakeles::fixtures::tcp_packet();
        let keys = project(&ir, &pkt).unwrap().unwrap();
        let golden = GoldenFile {
            kernel_version: "test".into(),
            keys_subset: vec![
                "nhoff".into(),
                "thoff".into(),
                "sport".into(),
                "dport".into(),
            ],
            entries: vec![GoldenEntry {
                packet_hex: pkt.iter().map(|b| format!("{b:02x}")).collect(),
                disposition: Disposition::Ok,
                keys: Some(keys),
            }],
        };
        let dir = std::env::temp_dir().join("pakeles_cli_diff_override");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("golden.json");
        std::fs::write(&path, serde_json::to_string(&golden).unwrap()).unwrap();
        let report = cli_diff(None, Some(&path)).unwrap();
        assert_eq!(report.compared, 1);
        assert!(report.mismatches.is_empty());
    }

    /// The diff binary's default path: discover the committed golden,
    /// diff, come back clean.
    #[test]
    fn cli_diff_discovers_committed_golden_and_agrees() {
        let report = cli_diff(None, None).unwrap();
        assert!(report.compared > 0);
        assert!(
            report.mismatches.is_empty(),
            "{}",
            report.mismatches.join("\n")
        );
    }

    /// Rung 1's definition of done: Pakeles's projected `flow_keys` agree
    /// with the kernel-captured goldens committed in
    /// `examples/real_world/linux_flow_dissector/conformance/` — goldens minted from
    /// upstream `bpf_flow.c` itself, covering the full corpus including
    /// VLAN/MPLS and agreement on kernel drops, not just accepts. If this
    /// fails, that's a real disagreement between our parse/projection and
    /// the kernel — investigate; do NOT edit the golden file to force
    /// green.
    #[test]
    fn committed_goldens_agree() {
        let dir = conformance_dir();
        let golden_path = discover_committed_golden(&dir).expect("a committed golden file exists");
        let g: GoldenFile =
            serde_json::from_str(&std::fs::read_to_string(golden_path).unwrap()).unwrap();
        let report = diff_goldens(&ir(), &g).unwrap();
        let ok = g
            .entries
            .iter()
            .filter(|e| e.disposition == Disposition::Ok)
            .count();
        let drop = g.entries.len() - ok;
        assert!(
            ok >= 39 && drop >= 18,
            "corpus shape shrank: {ok} ok / {drop} drop entries"
        );
        for name in [
            "nhoff",
            "thoff",
            "n_proto",
            "addr_proto",
            "ip_proto",
            "sport",
            "dport",
            "ipv4_src",
            "ipv4_dst",
            "ipv6_src",
            "ipv6_dst",
            "flow_label",
            "is_frag",
            "is_first_frag",
            "is_encap",
        ] {
            assert!(
                g.keys_subset.iter().any(|s| s == name),
                "golden keys_subset missing `{name}` — re-mint with the rung-4a capture.c \
                 (a subset-stale golden would silently skip the newer fields)"
            );
        }
        assert_eq!(report.compared, g.entries.len());
        assert!(
            report.mismatches.is_empty(),
            "Pakeles disagrees with the kernel flow dissector:\n{}",
            report.mismatches.join("\n")
        );
    }
}

#[cfg(test)]
mod gallery_tests {
    use super::*;

    #[test]
    fn embedded_ir_parses_and_validates() {
        pakeles::ir::validate::validate(&ir()).unwrap();
    }

    /// The committed ir.json must be exactly what the Rust canonical
    /// serializer emits — the anti-drift "canonical form" guard.
    #[test]
    fn committed_ir_json_is_canonical() {
        let committed =
            std::fs::read_to_string(dir().join("linux_flow_dissector.ir.json")).unwrap();
        let round = pakeles::ir::to_json(&pakeles::ir::from_json(&committed).unwrap()).unwrap();
        assert_eq!(
            round, committed,
            "committed ir.json is not in canonical form; regenerate: ./dev.sh scripts/gen-examples.sh"
        );
    }

    /// The mirrored .py must match the authoritative eDSL module.
    #[test]
    fn committed_py_example_current() {
        let canonical = std::fs::read_to_string(
            dir().join("../../../python/src/pakeles/examples/linux_flow_dissector.py"),
        )
        .unwrap();
        let mirrored = std::fs::read_to_string(dir().join("linux_flow_dissector.py")).unwrap();
        assert_eq!(
            canonical, mirrored,
            "examples/ drifted; regenerate: ./dev.sh scripts/gen-examples.sh"
        );
    }

    #[test]
    fn committed_gen_artifacts_current() {
        pakeles_testkit::committed_artifacts_current(&ir(), dir());
    }

    #[test]
    fn c_backend_conformance_full_suite() {
        pakeles_testkit::c_backend_conformance(
            &ir(),
            pakeles_testkit::committed_suite(dir()).as_ref(),
        );
    }

    #[test]
    fn bpf_backend_conformance_full_suite() {
        pakeles_testkit::bpf_backend_conformance(
            &ir(),
            pakeles_testkit::committed_suite(dir()).as_ref(),
        );
    }

    #[test]
    fn lua_backend_conformance_full_suite() {
        let Some(suite) = pakeles_testkit::committed_suite(dir()) else {
            return;
        };
        pakeles_testkit::lua_backend_conformance(&ir(), &suite, 400);
    }

    #[test]
    fn bmv2_backend_conformance_byte_aligned() {
        let Some(suite) = pakeles_testkit::committed_suite(dir()) else {
            return;
        };
        pakeles_testkit::bmv2_backend_conformance(&ir(), &suite, 90);
    }
}
