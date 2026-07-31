//! quic_initial golden factory: parse byte strings as QUIC packet
//! headers via TWO pinned oracles and emit both projections per entry.
//!
//!   quiche lane (primary, the agreement claim):
//!     `quiche::Header::from_slice(&mut buf, 0)` — dcid_len 0 because
//!     short-header DCID length is out-of-band config (the example
//!     treats short headers as classify-only).
//!   quinn lane (secondary, expected-divergence table):
//!     `ProtectedHeader::decode` with supported_versions=&[1],
//!     grease_quic_bit=false, FixedLengthConnectionIdParser::new(0).
//!
//! Per-lane verdicts:
//!   ok  — {"ty", "version", "dcid", "scid", "token", "len",
//!          "versions"}; fields the oracle does not expose for that
//!          packet shape are null. Each lane reports its oracle's OWN
//!          vocabulary (quiche "ZeroRTT"/"VersionNegotiation" vs quinn
//!          "ZeroRtt"/"VersionNegotiate"; quiche short version=0 vs
//!          quinn version=null) — the example's comparator owns the
//!          mapping, the golden stays faithful.
//!   err — {"error"}: quiche Debug ("BufferTooShort"/"InvalidPacket"),
//!          quinn Display ("invalid header: ..."/"unsupported version
//!          ...") — both stable at the pins.
//!
//! Modes:
//!   capture <corpus.txt>   corpus lines (# comments, blank, hex; a
//!                          lone "-" is the EMPTY packet) → JSON
//!   one <hex|->            project a single packet (debug/smoke aid)

use std::io::Write as _;

use quinn_proto::{FixedLengthConnectionIdParser, ProtectedHeader};

fn hex_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    if s == "-" {
        // Corpus marker for the empty packet (a blank line would be
        // skipped as formatting).
        return Ok(Vec::new());
    }
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    anyhow::ensure!(s.len() % 2 == 0, "odd-length hex");
    (0..s.len() / 2)
        .map(|i| Ok(u8::from_str_radix(&s[2 * i..2 * i + 2], 16)?))
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn quiche_lane(bytes: &[u8]) -> serde_json::Value {
    let mut buf = bytes.to_vec();
    match quiche::Header::from_slice(&mut buf, 0) {
        Ok(h) => serde_json::json!({
            "verdict": "ok",
            "ty": format!("{:?}", h.ty),
            "version": h.version,
            "dcid": hex(&h.dcid),
            "scid": hex(&h.scid),
            "token": h.token.as_deref().map(hex),
            "len": serde_json::Value::Null, // quiche never parses length
            "versions": h.versions,
        }),
        Err(e) => serde_json::json!({
            "verdict": "err",
            "error": format!("{e:?}"),
        }),
    }
}

fn quinn_lane(bytes: &[u8]) -> serde_json::Value {
    let mut cur = std::io::Cursor::new(bytes::BytesMut::from(bytes));
    let decoded = ProtectedHeader::decode(
        &mut cur,
        &FixedLengthConnectionIdParser::new(0),
        &[0x0000_0001],
        false,
    );
    match decoded {
        Ok(ProtectedHeader::Initial(h)) => serde_json::json!({
            "verdict": "ok",
            "ty": "Initial",
            "version": h.version,
            "dcid": hex(&h.dst_cid),
            "scid": hex(&h.src_cid),
            // token_pos indexes the original packet bytes.
            "token": hex(&bytes[h.token_pos.clone()]),
            "len": h.len,
            "versions": serde_json::Value::Null,
        }),
        Ok(ProtectedHeader::Long { ty, dst_cid, src_cid, len, version }) => {
            serde_json::json!({
                "verdict": "ok",
                "ty": format!("{ty:?}"), // Handshake | ZeroRtt
                "version": version,
                "dcid": hex(&dst_cid),
                "scid": hex(&src_cid),
                "token": serde_json::Value::Null,
                "len": len,
                "versions": serde_json::Value::Null,
            })
        }
        Ok(ProtectedHeader::Retry { dst_cid, src_cid, version }) => {
            serde_json::json!({
                "verdict": "ok",
                "ty": "Retry",
                "version": version,
                "dcid": hex(&dst_cid),
                "scid": hex(&src_cid),
                "token": serde_json::Value::Null, // quinn exposes no Retry token
                "len": serde_json::Value::Null,
                "versions": serde_json::Value::Null,
            })
        }
        Ok(ProtectedHeader::Short { spin: _, dst_cid }) => serde_json::json!({
            "verdict": "ok",
            "ty": "Short",
            "version": serde_json::Value::Null,
            "dcid": hex(&dst_cid), // "" — factory passes dcid_len 0
            "scid": serde_json::Value::Null,
            "token": serde_json::Value::Null,
            "len": serde_json::Value::Null,
            "versions": serde_json::Value::Null,
        }),
        Ok(ProtectedHeader::VersionNegotiate { random: _, dst_cid, src_cid }) => {
            serde_json::json!({
                "verdict": "ok",
                "ty": "VersionNegotiate",
                "version": serde_json::Value::Null,
                "dcid": hex(&dst_cid),
                "scid": hex(&src_cid),
                "token": serde_json::Value::Null,
                "len": serde_json::Value::Null,
                // quinn does NOT walk the VN version list (the example
                // sides with this stance; quiche's walked list is in
                // ITS lane).
                "versions": serde_json::Value::Null,
            })
        }
        Err(e) => serde_json::json!({
            "verdict": "err",
            "error": e.to_string(),
        }),
    }
}

fn project(bytes: &[u8]) -> serde_json::Value {
    serde_json::json!({
        "quiche": quiche_lane(bytes),
        "quinn": quinn_lane(bytes),
    })
}

fn capture(corpus_path: &str) -> anyhow::Result<()> {
    let corpus = std::fs::read_to_string(corpus_path)?;
    let mut entries = Vec::new();
    for line in corpus.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let bytes = hex_decode(line)?;
        let mut entry = project(&bytes);
        entry["hex"] = serde_json::Value::String(hex(&bytes));
        entries.push(entry);
    }
    let out = serde_json::json!({
        "quiche": std::env::var("QUICHE_VERSION").unwrap_or_default(),
        "quinn-proto": std::env::var("QUINN_PROTO_VERSION").unwrap_or_default(),
        "entries": entries,
    });
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer_pretty(&mut stdout, &out)?;
    writeln!(stdout)?;
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("capture") => {
            capture(args.get(2).map(String::as_str).unwrap_or("corpus.txt"))
        }
        Some("one") => {
            let bytes = hex_decode(args.get(2).expect("hex arg"))?;
            println!("{}", project(&bytes));
            Ok(())
        }
        _ => anyhow::bail!("usage: capture <corpus.txt> | one <hex|->"),
    }
}
