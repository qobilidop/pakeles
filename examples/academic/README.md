# `academic/` — descriptions reproduced from published evaluations

Each example here transcribes a parser that a published paper
evaluated, cited to source. The point is **comparability**: the full
Pakeles pipeline — state counts, symbolic-execution path counts and
witness suites, and all backends — runs over the same artifacts the
literature reports numbers for, so our measurements sit next to
published ones. Nothing here is an agreement claim: there is no
runnable incumbent to diff against (contrast `../real_world/`), and
the gate is the same battery the synthetic gallery runs (committed
artifacts current + backend conformance over the symex suite, in
`rust/pakeles/tests/academic_gallery.rs`).

Current members:

| Example (here) | Source | Item |
|---|---|---|
| `gibb_simple/` | Gibb et al., ANCS 2013 (artifact/thesis only) | "simple" parse graph |
| `gibb_enterprise/` | Gibb et al., ANCS 2013, Fig. 3a | "Enterprise" |
| `gibb_datacenter/` | Gibb et al., ANCS 2013, Fig. 3b | "Data center" |
| `gibb_edge/` | Gibb et al., ANCS 2013, Fig. 3c | "Edge" |
| `gibb_service_provider/` | Gibb et al., ANCS 2013, Fig. 3d | "Service provider" |
| `gibb_big_union/` | Gibb et al., ANCS 2013, Fig. 3e | "big-union" (28 nodes, 677 paths) |
| `kangaroo_parse_tree/` | Kozanitis et al., INFOCOM 2010, §VII | the (unnamed) Cisco parse tree |

The four `gibb_*` scenario graphs are also the "Applicability"
benchmarks of **Leapfrog** (Doenges et al., PLDI 2022, §7.2), which
certified parser equivalences over them — one transcription, two
literatures of comparison numbers.

## Naming

Extends the `real_world/` scheme (`<namespace>_<component>`; read
that README first):

- **Namespace: the work's own brand name if it has one** (`kangaroo`,
  `leapfrog`, `everparse`), **else the first author's surname**
  (`gibb` — "parser-gen" is generic, and the literature attributes
  the graphs to Gibb et al.; Leapfrog's citation does exactly this).
- **Component: the item's name in the work's primary figure or
  table**, snake-cased ("big-union" → `big_union`). When the work
  itself spells a multi-word name both ways, prefer its compact
  artifact spelling (`datacenter`, per `headers-datacenter.txt` and
  Leapfrog's "Datacenter", over Fig 3's caption "Data center").
  In-corpus aliases (the same graph is "Edge" in Fig 3,
  "Enterprise Edge" in Fig 15, "Core router" in RMT/the thesis) are
  recorded in the example's README, never invented into the name.
  **Where the work doesn't name its item, use the work's own noun
  for it** — `kangaroo_parse_tree`, by the same rule that produced
  `katran_parser`.
- **Derived items belong to their origin namespace.** A downstream
  work that reuses another's suite (Leapfrog reusing Gibb's graphs)
  gets entries only for items it adds; the shared items live once,
  under the origin, with the downstream work cited as a consumer.
- **Fixed published items only.** Parameterized benchmark generators
  (Whippersnapper) are bench tooling, not gallery members. Grammars
  that require IR this project deliberately declines (Nail's DNS
  label compression and ZIP offsets — backward references) are
  citations in docs, not members.

## Licensing rule

**Transcribe facts from the papers; never vendor or copy artifact
files.** Graph structure, dispatch values, and repetition bounds are
facts; every `.py` here is original expression. This matters
concretely: `grg/parser-gen`'s LICENSE file is empty (no license
granted), so its files are reference-only — nothing from them may be
committed here.

## What every example README must carry

- **Source**: full citation, the exact figure/table transcribed, and
  the artifact reference where one exists.
- **Transcription notes**: every interpretive choice, named — and no
  silent "fixes" of the source. The source is the source, quirks
  included (the data-center graph's VXLAN port is 65535 because the
  paper predates the 4789 assignment; it stays 65535).
