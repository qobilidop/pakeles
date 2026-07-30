# `synthetic/` — formats constructed to isolate one capability

These descriptions were built for this repo rather than found in the
world. Each one exercises a single IR capability in the smallest form
that still generates every artifact, which makes them the regression
anchors the engine work leans on: when a capability lands, its
synthetic example lands with it and guards it thereafter.

| Example | Isolates |
|---|---|
| `eth_ipvx_l4/` | branching demux — Ethernet → {IPv4, IPv6} → {TCP, UDP}; the hello-world |
| `counted_items/` | parse metadata — a count-prefixed accumulator loop with a select-on-metadata exit |
| `tlv_items/` | sized regions — a length-bounded TLV loop closed by exact exhaustion |

Being synthetic does not mean being disposable. `tlv_items/` is what
guards the entire sized-region slice, and `eth_ipvx_l4/` is embedded in
the crate and used as the CLI's default description.

One wrinkle worth naming: `eth_ipvx_l4/` parses genuine Ethernet, IPv4,
IPv6, TCP and UDP. It sits here because the *description* is a
constructed simplification — it models no particular implementation and
has no incumbent to be checked against, which is precisely what
separates this group from `../real_world/`.
