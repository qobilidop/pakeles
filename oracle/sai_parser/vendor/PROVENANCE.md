# Vendored SONiC PINS `sai_p4` parser (incumbent)

These files are copied **verbatim** from
[sonic-net/sonic-pins](https://github.com/sonic-net/sonic-pins) at pinned
commit **`e77250b8dcab96e6f0e6ba1a9643f66771caa46c`** (main, 2026-04-27):

| vendored path | upstream path |
|---|---|
| `parser/sai_parser.p4` | `p4_symbolic/testdata/parser/sai_parser.p4` |
| `common/headers.p4` | `p4_symbolic/testdata/common/headers.p4` |
| `common/bitwidths.p4` | `p4_symbolic/testdata/common/bitwidths.p4` |
| `common/sai_ids.p4` | `p4_symbolic/testdata/common/sai_ids.p4` |

## License

SONiC PINS is licensed **Apache-2.0** (© Google LLC and contributors).
The full license text is at
<https://github.com/sonic-net/sonic-pins/blob/main/LICENSE>. These files
are redistributed here unmodified, under that license, solely as the
pinned incumbent for the `sai_parser` conformance oracle. Vendoring is
permitted by Apache-2.0 (contrast the GPL katran sources, which are
fetched at capture time and never committed).

## Derivation

`oracle/sai_parser/factory/instrument.py` applies a small, clearly-marked
observation patch (a validity-bitmap verdict header, forwarding, and a
verdict-only deparser) to a *copy* of `parser/sai_parser.p4` at capture
time — the vendored copy here stays pristine. The patch is Pakeles's
own work (not upstream) and only makes the parse observable on
`simple_switch`; it does not change the parser's behavior.
