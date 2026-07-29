//! tls_clienthello golden factory: parse byte strings as the first TLS
//! flight via rustls's public `Acceptor` API (bytes in → `ClientHello`
//! accessor or typed error out; no connection state, no privileges) and
//! emit the projection as JSON.
//!
//! Verdicts:
//!   accept     — rustls produced an `Accepted` (a parsed ClientHello)
//!   incomplete — rustls consumed everything and still wants more bytes
//!                (truncated record / handshake); maps to PacketTooShort
//!   reject     — rustls returned an error (`err` carries the Debug form)
//!
//! Modes:
//!   capture <corpus.txt>   corpus lines (# comments, blank, hex) → JSON
//!   selftest               rustls client mints a real CH; assert we
//!                          project verdict=accept + the right SNI
//!   one <hex>              project a single packet (debug aid)

use std::io::Write as _;
use std::sync::Arc;

fn hex_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    anyhow::ensure!(s.len() % 2 == 0, "odd-length hex");
    (0..s.len() / 2)
        .map(|i| Ok(u8::from_str_radix(&s[2 * i..2 * i + 2], 16)?))
        .collect()
}

fn project(bytes: &[u8]) -> serde_json::Value {
    let mut acceptor = rustls::server::Acceptor::default();
    let mut cursor = bytes;
    loop {
        // Feed until the acceptor stops making progress, checking after
        // every chunk: read_tls errors on malformed record framing,
        // accept() errors on malformed handshake content.
        match acceptor.read_tls(&mut cursor) {
            Ok(_) => {}
            Err(e) => {
                return serde_json::json!({
                    "verdict": "reject",
                    "err": format!("read_tls: {e:?}"),
                });
            }
        }
        match acceptor.accept() {
            Ok(Some(accepted)) => {
                let ch = accepted.client_hello();
                let suites: Vec<u16> =
                    ch.cipher_suites().iter().map(|s| u16::from(*s)).collect();
                let alpn: Option<Vec<String>> = ch.alpn().map(|it| {
                    it.map(|p| {
                        p.iter().map(|b| format!("{b:02x}")).collect::<String>()
                    })
                    .collect()
                });
                return serde_json::json!({
                    "verdict": "accept",
                    "sni": ch.server_name(),
                    "cipher_suites": suites,
                    "alpn": alpn,
                });
            }
            Ok(None) => {
                if cursor.is_empty() {
                    return serde_json::json!({ "verdict": "incomplete" });
                }
                // more input still buffered locally: keep feeding
            }
            Err((e, _alert)) => {
                return serde_json::json!({
                    "verdict": "reject",
                    "err": format!("{e:?}"),
                });
            }
        }
    }
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
        entry["hex"] = serde_json::Value::String(line.to_string());
        entries.push(entry);
    }
    let out = serde_json::json!({
        "rustls_version": std::env::var("RUSTLS_VERSION").unwrap_or_default(),
        "entries": entries,
    });
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer_pretty(&mut stdout, &out)?;
    writeln!(stdout)?;
    Ok(())
}

/// Mint a genuine first flight with rustls's own client and check we
/// project it as accept with the right SNI.
fn selftest() -> anyhow::Result<()> {
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    let mut conn = rustls::ClientConnection::new(
        Arc::new(config),
        "selftest.example".try_into()?,
    )?;
    let mut flight = Vec::new();
    conn.write_tls(&mut flight)?;
    anyhow::ensure!(!flight.is_empty(), "client produced no bytes");
    let proj = project(&flight);
    anyhow::ensure!(
        proj["verdict"] == "accept",
        "selftest CH not accepted: {proj}"
    );
    anyhow::ensure!(
        proj["sni"] == "selftest.example",
        "selftest SNI wrong: {proj}"
    );
    // A truncated prefix of the same flight must be incomplete, and
    // garbage must reject — the three-verdict surface end to end.
    let trunc = project(&flight[..flight.len() / 2]);
    anyhow::ensure!(
        trunc["verdict"] == "incomplete",
        "truncated CH not incomplete: {trunc}"
    );
    let garbage = project(b"\xde\xad\xbe\xef\xde\xad\xbe\xef");
    anyhow::ensure!(
        garbage["verdict"] == "reject",
        "garbage not rejected: {garbage}"
    );
    println!("selftest ok: {proj}");
    Ok(())
}

fn main() -> anyhow::Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("install ring provider");
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("capture") => capture(args.get(2).map(String::as_str).unwrap_or("corpus.txt")),
        Some("selftest") => selftest(),
        Some("one") => {
            let bytes = hex_decode(args.get(2).expect("hex arg"))?;
            println!("{}", project(&bytes));
            Ok(())
        }
        _ => anyhow::bail!("usage: capture <corpus.txt> | selftest | one <hex>"),
    }
}
