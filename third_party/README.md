# `third_party/` — the only tree where third-party code lives

**The licensing rule is one sentence: if code wasn't written for this
repo, it lives (or lands) here, and nowhere else.**

- `sonic-pins/` — Apache-2.0 sources copied verbatim from
  [sonic-net/sonic-pins](https://github.com/sonic-net/sonic-pins) at a
  pinned commit (see `sonic-pins/PROVENANCE.md`). Consumed by
  `examples/real_world/sai_parser/factory/`.
- `dash/` — Apache-2.0 sources copied verbatim from
  [sonic-net/DASH](https://github.com/sonic-net/DASH) at a pinned
  commit (see `dash/PROVENANCE.md`). Consumed by
  `examples/real_world/dash_parser/factory/`.
- Katran's GPL-2.0 sources are **fetch-only**: they land in a
  gitignored build directory at capture time
  (`examples/real_world/katran_parser/factory/fetch.sh`) and are
  deliberately never committed.

Everything else in the repo — including every `factory/` and `spike/`
under `examples/real_world/` (capture harnesses, corpora, eBPF
loaders) — is ours.
