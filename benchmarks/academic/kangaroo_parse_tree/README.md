# `kangaroo_parse_tree` — the Kangaroo system's Cisco parse tree

The single evaluation input of the Kangaroo wire-speed parser paper:
a parse tree "supported by several Cisco routers" — Ethernet, six
shim headers, MPLS(≤4), ARP/RARP, IPv4/IPv6 with GRE/ESP/ICMP and
one level of tunneling, and an IPv6 extension header. The paper never
names it; per the group's naming rule the component falls back to the
work's own noun, "parse tree."

## Source

- Christos Kozanitis, John Huber, Sushil Singh, George Varghese.
  *Leaping Multiple Headers in a Single Bound: Wire-Speed Parsing
  Using the Kangaroo System.* IEEE INFOCOM 2010, §VII.
- The source is **prose only** — one paragraph of §VII naming each
  header's possible successors. There is no figure, no artifact, no
  field layout, no dispatch value, and no next-header mechanism in
  the paper. This is the group's only prose-sourced member, so the
  notes below carry more weight than usual: everything beyond the
  successor sets is supplied by this transcription.

The prose's successor sets, restated: Ethernet may be followed by the
shims 802.1Q, nested 802.1Q, recirc tag, service tag, 802.1ah, and
802.1ad; Ethernet and every shim may be followed by up to four MPLS
headers, ARP, RARP, IPv4, or IPv6; MPLS by Ethernet, IPv4, or IPv6;
IPv4/IPv6 by TCP, UDP, GRE, ESP, ICMP, or a second IPv4 header; IPv6
also by one extension header, which is followed by TCP, UDP, ESP, or
ICMPv6; GRE also by IPv4/IPv6. The paper adds that the tree supports
up to three lengths for IPv4 and up to eight for GRE.

## Transcription notes

Every choice below is interpretive; the prose constrains only the
successor sets.

- **Layouts and dispatch values are ours.** Standard header layouts
  and IEEE/IANA registry values throughout (802.1Q 0x8100, 802.1ad
  0x88A8, 802.1ah 0x88E7, MPLS 0x8847/0x8848, ARP 0x0806, RARP
  0x8035, IPv4 0x0800, IPv6 0x86DD).
- **Placeholder EtherTypes for the Cisco-internal tags.** The recirc
  and service tags are Cisco-internal shims whose EtherTypes are
  unpublished; they are reached here via clearly-marked placeholder
  values (recirc 0xF000, service 0xF100), labeled as placeholders in
  the enum and here. "Resirc" is the paper's own spelling [sic].
- **One shared shim layout.** Five of the six shims (802.1Q ×2,
  recirc, service, 802.1ad) share one 4-byte 802.1Q-shaped `ShimTag`
  type — the recirc/service shape is itself an interpretive choice.
  The shim's identity lives in the state path. 802.1ah gets its own
  PBB layout, but — unlike Gibb's PBB node, which runs straight into
  an inner Ethernet — it ends in a 16-bit EtherType and dispatches
  like every other shim, because the prose says all shims can be
  followed by MPLS/ARP/RARP/IPv4/IPv6.
- **Nested 802.1Q exactly once.** "Nested 802.1q" is enumerated as
  its own shim, so `parse_vlan_q1` → `parse_vlan_q2` and no third
  tag; no other shim nests.
- **ARP and RARP merged.** The prose lists them separately but gives
  no layouts; one `ArpRarp` node (standard 8-byte prefix, terminal,
  no ARP body — the prose mentions none) is reached from both
  EtherTypes.
- **MPLS mechanism borrowed from the Gibb suite.** The prose gives
  no mechanism for MPLS's successor, only the set {Ethernet, IPv4,
  IPv6}. Borrowed: each label state selects on `bos`; at bottom of
  stack a `lookahead(MplsPayloadNibble)` peeks the discriminator and
  dispatches 0 → inner Ethernet, 4 → `Ipv4`, 6 → `Ipv6`. Unlike Gibb
  there is no EoMPLS control word in this tree, and since 2026-08-01
  that costs nothing: the peek consumes no bits, so the inner
  Ethernet begins exactly at the payload. *The previous encoding
  consumed the nibble, which meant the discriminator occupied the
  four bits ahead of the inner frame — a recorded artifact of the
  borrowed mechanism that the `lookahead` primitive removed outright,
  along with the `Ipv4Rest`/`Ipv6Rest` continuations.* The inner
  Ethernet is terminal (the prose gives it no successors).
- **IPv4 dispatches on protocol alone.** The prose never mentions
  fragments, so no `(fragOffset, protocol)` concatenation (differs
  from the Gibb graphs). The "second IPv4 header" is IP-in-IP,
  protocol 4, from both IPv4 and IPv6.
- **IPv6 readings.** The extension header is reached via next-header
  0 (Hop-by-Hop — the canonical extension-header value; the prose
  does not say which). ICMP (protocol 1) is allowed directly after
  IPv6 — the prose lists ICMP among the followers of "IPv4/IPv6" —
  while ICMPv6 (58) appears only after the extension header, exactly
  where the prose puts it. One extension header ("an ... extension
  header"), standard two-byte prefix plus an 8-octet-unit body.
- **One tunnel level.** The prose describes a finite tree, so
  IPv4-in-IP and GRE's inner IPv4/IPv6 dispatch L4 only ({TCP, UDP,
  ESP, ICMP}) — no further GRE or IP-in-IP, and the inner IPv6 does
  not re-enter the extension-header chain.
- **"Three lengths for IPv4, eight for GRE."** That remark describes
  the paper's TCAM entry binning, not distinct grammars. Here IPv4's
  IHL-driven options field covers every length natively, and GRE's
  flag-driven optional words (`var_bytes(c*4 + k*4 + s*4)`) cover
  all 2³ = 8 C/K/S combinations. GRE's case-distinct `S`/`s` flags
  become fields `s`/`strict`.
- **Unmatched dispatch = accept**, the academic group's shared
  semantic: an unrecognized value ends the recognized sequence; the
  tree classifies, it does not validate.
- **IPv6 addresses.** 128-bit source/destination addresses exceed
  the eDSL's fixed-`bits` ceiling (64), so they are carried as
  constant-length opaque 16-byte runs (`var_bytes(16)` — same bits
  consumed, value-opaque), the house idiom from
  `linux_flow_dissector`.
- **`max_depth = 13`**: the deepest path is 12 headers — Ethernet,
  two 802.1Q tags, four MPLS labels, the peeked payload nibble,
  `Ipv4`, GRE, an inner IP header, one L4 header — plus one. The peek
  costs a state but consumes no bits.
