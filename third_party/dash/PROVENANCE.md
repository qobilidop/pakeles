# Vendored DASH BMv2 pipeline parser (incumbent)

These files are copied **verbatim** from
[sonic-net/DASH](https://github.com/sonic-net/DASH) at pinned commit
**`d5c003dd7774c2b43f275c0233acc73a0ea28d2f`** (main, 2026-05-28):

| vendored path | upstream path |
|---|---|
| `dash_parser.p4` | `dash-pipeline/bmv2/dash_parser.p4` |
| `dash_headers.p4` | `dash-pipeline/bmv2/dash_headers.p4` |

`dash_parser.p4`'s only `#include` is `dash_headers.p4`, which includes
nothing — the 20 pipeline-stage includes of `dash_pipeline.p4` are not
needed to compile the parser. Two symbols the parser references live
outside these files upstream and are supplied by the capture harness
(not vendored, each a one-liner mirrored with a provenance comment in
`instrument.py`): `typedef dash_flow_action_t dash_routing_actions_t;`
(`dash-pipeline/bmv2/dash_metadata.p4` line 9 at the pin) and the
`metadata_t` struct (the parser threads `meta` through without touching
it, so the harness's empty struct is behavior-identical).

## License

DASH is licensed **Apache-2.0** (© Microsoft Corporation and
contributors). The full license text is at
<https://github.com/sonic-net/DASH/blob/main/LICENSE>. These files are
redistributed here unmodified, under that license, solely as the pinned
incumbent for the `dash_parser` conformance oracle. Vendoring is
permitted by Apache-2.0 (contrast the GPL katran sources, which are
fetched at capture time and never committed).

## Derivation

`examples/real_world/dash_parser/factory/instrument.py` does not modify
these files at all: it generates a minimal v1model wrapper program
(`factory/build/main.p4`) that `#include`s the vendored parser
unchanged, runs it as a sub-parser, and adds a verdict header (a
header-validity bitmap, the parser error code, and four key parsed
fields) that the wrapper's own deparser emits. The wrapper is Pakeles's
own work (not upstream) and only makes the parse observable on
`simple_switch`; it does not change the parser's behavior.
