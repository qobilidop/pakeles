# Pakeles IR: operational semantics

**Status: normative.** This document and the reference interpreter
(`rust/pakeles/src/interp`) are jointly normative for IR `v1alpha1` as
defined in `proto/pakeles/ir/v1alpha1/ir.proto`. On any divergence,
this document wins and the interpreter has a bug. The well-formedness
conditions of §2 are implemented by `rust/pakeles/src/ir/validate.rs`;
the dynamic semantics of §4 by `rust/pakeles/src/interp`. Every other
consumer — symbolic executor, code generators, documentation and
dissector backends — must agree with the interpreter over well-formed
IR, and that agreement is checked continuously by the test-vector
suites.

Two constructs are deliberately absent from every rule below:
`Display` (and its `ValueLabel`s) and the free-form `annotations`
maps. No judgment reads them; they cannot affect any outcome. The one
carve-out is `Reject.annotations["severity"]`, which classifies a
reject for diagnostic consumers (§4.8) without changing the outcome
itself.

## 1. Notation and domains

An IR program is a `Parser` message; we write

- $Q$ — the set of state names, $q_0 \in Q$ the start state,
- $D \in \mathbb{N}_{\ge 1}$ — `max_depth`,
- $\mathrm{HT}$ — the header types; each type $h$ is an ordered list
  of fields, each field either fixed-width ($n$ bits, $1 \le n \le
  64$) or variable-length (`byte_len` expression),
- $M$ — the metadata declarations; each $m \in M$ has a width
  $w_m \in [1,64]$ and initial value $\mathit{init}_m < 2^{w_m}$.

All numeric values are elements of $\mathbb{Z}_{2^{64}}$ (unsigned
64-bit); arithmetic is modulo $2^{64}$ throughout.

The input is a finite bit string $\pi$ of length $|\pi|$ bits
(inputs may end mid-byte). Bits are addressed $0 \ldots |\pi|-1$;
bit reads are big-endian across bytes and MSB-first within a byte:

$$
\mathrm{read}(\pi, c, n) \;=\; \sum_{i=0}^{n-1} 2^{\,n-1-i}\,\pi[c+i]
\qquad \text{defined iff } c+n \le |\pi| .
$$

A **configuration** is a tuple

$$
\sigma \;=\; \langle q,\; c,\; \rho,\; \mu,\; R,\; d \rangle
$$

where $q \in Q$ is the current state, $c$ the cursor (a bit offset
into $\pi$), $\rho$ the field environment (a finite map from
*(instance name, field name)* pairs to values — later extractions of
the same instance overwrite earlier ones), $\mu$ the metadata store (a
total map over $M$, always satisfying $\mu(m) < 2^{w_m}$), $R$ the
region stack (a sequence of absolute bit offsets, innermost last), and
$d$ the number of states entered so far.

The initial configuration is $\sigma_0 = \langle q_0,\, 0,\,
\varnothing,\, \mu_0,\, \epsilon,\, 0 \rangle$ with $\mu_0(m) =
\mathit{init}_m$.

Terminal results are $\mathbf{Accept}\langle c, \mu \rangle$ and
$\mathbf{Reject}\langle \mathit{reason}, c, \mu \rangle$: the outcome,
the bits consumed when parsing stopped, and the final metadata
snapshot. The extracted headers (each instance's fields with their
offsets and values, in extraction order) and the trace (the sequence
of states entered with the transition decision taken in each) are
further observables; both are read off the derivation itself and need
no extra machinery.

**Region bound.** Reads are bounded jointly by the innermost region
and the input:

$$
\mathrm{bound}(R) \;=\;
\begin{cases}
\min(\mathrm{top}(R),\, |\pi|) & R \ne \epsilon \\
|\pi| & R = \epsilon
\end{cases}
$$

**Reject classes.** Every reject reason below is a normative string.
Reasons divide into the *truncation class* (`out of bounds` — the
input ended before consistent content did; incumbent semantics "need
more bytes") and the *structural class* (everything else — the
content itself is inconsistent). The class determines which reason a
failed read reports, per rule.

## 2. Static semantics (well-formedness)

A `Parser` is **well-formed** iff all of the following hold. The
dynamic semantics is defined only over well-formed programs.

- **W1 (bound).** $D \ge 1$.
- **W2 (names).** Header type names, field names within a type,
  metadata names, and state names are unique and non-empty; the start
  state exists; every state-target of every transition names an
  existing state.
- **W3 (widths).** Fixed field widths and metadata widths lie in
  $[1, 64]$; each metadata `init` fits its width.
- **W4 (byte_len purity).** A `byte_len` expression references only
  header fields and constants: no metadata references, no
  `remaining()`.
- **W5 (push purity).** A region-push length expression references
  only header fields and constants: no metadata references, no
  `remaining()`.
- **W6 (select shape).** Every arm has exactly one keyset entry per
  key; when a key is a plain field or metadata reference of width
  $w$, every value, mask, and range endpoint in its entries fits in
  $w$ bits. A reject severity annotation, if present, is `"error"` or
  `"info"`. (A `masked` entry may carry value bits outside its mask;
  matching masks both sides, §3, so such bits are inert.)
- **W7 (definite extraction).** Every field reference — in widths,
  assigns, push lengths, and select keys — names an instance that is
  extracted on *every* path from the start state to the use point
  (must-analysis over the state graph; an instance extracted earlier
  in the same state, or earlier in the same header for `byte_len`
  widths, counts).
- **W8 (region depth).** Every reachable state is entered at exactly
  one region-stack depth; no pop on an empty stack; `remaining()`
  appears only where a region is provably open — in assigns, the
  state's entry depth is positive; in select keys, the depth after
  the state's region ops is positive. Depth consistency implies the
  region stack is bounded.

Well-formedness is decidable (all conditions are finite checks or
monotone fixpoints over the finite state graph) and is checked by
`validate()` before any execution.

**Alignment.** Variable-length extraction, region push, and
`remaining()` additionally require a byte-aligned cursor ($8 \mid c$).
This is *not* currently guaranteed by W1–W8: a well-formed program
that reaches such an operation misaligned is in **specification
fault** — the run is an error of the program, not an outcome for the
packet (the interpreter raises an engine error, distinct from any
reject). All shipped frontends only emit aligned programs; tightening
this into a static check is a recorded candidate for a future
validator revision.

## 3. Expression evaluation

Expressions are evaluated in a context $(\rho, \mu, r)$ where $r \in
\mathbb{Z}_{2^{64}} \cup \{\bot\}$ is the value of `remaining()` at
this use point ($\bot$ where illegal; W4/W5/W8 ensure $\bot$ is never
consulted). Evaluation $[\![ e ]\!]_{\rho,\mu,r}$ is total on
well-formed programs:

$$
[\![ k ]\!] = k
\qquad
[\![ \mathit{fld}(i,f) ]\!] = \rho(i,f)
\qquad
[\![ \mathit{meta}(m) ]\!] = \mu(m)
\qquad
[\![ \mathit{remaining} ]\!] = r
$$

$$
[\![ e_1 \mathbin{op} e_2 ]\!] =
[\![ e_1 ]\!] \mathbin{op} [\![ e_2 ]\!] \bmod 2^{64}
\quad op \in \{+, -, \times, \mathbin{\&}, \mathbin{|}\}
$$

Shifts take their right operand modulo 64:

$$
[\![ e_1 \ll e_2 ]\!] = [\![ e_1 ]\!] \cdot 2^{([\![ e_2 ]\!] \bmod 64)} \bmod 2^{64}
\qquad
[\![ e_1 \gg e_2 ]\!] = \left\lfloor [\![ e_1 ]\!] / 2^{([\![ e_2 ]\!] \bmod 64)} \right\rfloor
$$

Metadata reads zero-extend by construction: stores maintain $\mu(m) <
2^{w_m}$ (§4.4), and a read returns the stored value unchanged.

**`remaining()`** is *structural*: distance to the innermost region
end, with no input clamp —

$$
r \;=\; (\mathrm{top}(R) - c)/8
\qquad \text{when } R \ne \epsilon \text{ and } 8 \mid c
$$

(the subtraction cannot go negative: reads never cross the region
end, so $c \le \mathrm{top}(R)$ is invariant). It may exceed the
bytes actually present in $\pi$; a region that promises more than the
input holds is discovered by the *reads* it licenses (truncation
class), not by `remaining()` itself.

**Keyset matching.** A key value $k$ matches an entry as follows;
matching is total:

$$
k \models \mathit{value}(v) \iff k = v
\qquad
k \models \mathit{masked}(v, m) \iff k \mathbin{\&} m = v \mathbin{\&} m
\qquad
k \models \mathit{range}(lo, hi) \iff lo \le k \le hi
$$

## 4. Dynamic semantics

One machine step runs the current state to its transition decision:
extracts, then assigns, then region ops, then the transition — each
phase in declared order. We give the phases as sequential judgments;
any phase may terminate the run with a reject, which short-circuits
the rest of the state and the machine.

### 4.1 State entry and the depth budget

Entering a state increments $d$; the budget check precedes all work:

$$
\dfrac{d + 1 > D}
{\langle q, c, \rho, \mu, R, d \rangle \;\longrightarrow\;
\mathbf{Reject}\langle \texttt{max depth exceeded},\, c,\, \mu \rangle}
\quad \text{(R-Depth)}
$$

Otherwise the state body runs with $d' = d + 1$. The budget counts
*states entered*, including the entry that trips the bound; nothing a
program does — no assign, no region — can extend it.

### 4.2 Extraction: fixed-width fields

Each extract instantiates its header type by reading that type's
fields in order. For a fixed field $f$ of $n$ bits with the cursor at
$c$, let $B = \mathrm{bound}(R)$:

$$
\dfrac{c + n \le B \qquad v = \mathrm{read}(\pi, c, n)}
{\langle f, c \rangle \;\Downarrow\; \langle \rho[(i,f) \mapsto v],\; c + n \rangle}
\quad \text{(E-Fixed)}
$$

$$
\dfrac{c + n > B \qquad R \ne \epsilon \qquad c + n > \mathrm{top}(R)}
{\langle f, c \rangle \;\Downarrow\;
\mathbf{Reject}\langle \texttt{out of region bounds},\, c,\, \mu \rangle}
\quad \text{(E-Fixed-Region)}
$$

$$
\dfrac{c + n > B \qquad (R = \epsilon \;\lor\; c + n \le \mathrm{top}(R))}
{\langle f, c \rangle \;\Downarrow\;
\mathbf{Reject}\langle \texttt{out of bounds},\, c,\, \mu \rangle}
\quad \text{(E-Fixed-Trunc)}
$$

Crossing the innermost region end is structural — the region's
declared length promised content that is not there. Failing only
against the input end is truncation. The updated $\rho$ is visible
immediately: a later field of the *same* header may use $f$ in its
`byte_len` (W7 licenses exactly this).

### 4.3 Extraction: variable-length fields

For a variable-length field $f$ with length expression $e$ (bytes),
requires $8 \mid c$ (else specification fault, §2):

$$
\ell = [\![ e ]\!]_{\rho,\mu,\bot} \qquad
\mathit{end} = c + 8\ell \ \text{(overflow-checked)}
$$

$$
\dfrac{\mathit{end} \le B}
{\langle f, c \rangle \;\Downarrow\; \langle \rho,\; \mathit{end} \rangle}
\quad \text{(E-Var)}
$$

with the byte run $\pi[c \,..\, \mathit{end})$ recorded as the
field's value. On $\mathit{end} > B$ or arithmetic overflow, reject
with the same two-class reason rule as E-Fixed-Region/-Trunc (an
overflowed end counts as crossing every bound, hence structural when
a region is open). Note $\ell$ is the *wrapped* $\mathbb{Z}_{2^{64}}$
value of $e$ — a length expression that wraps (e.g. `ihl*4-20` with
`ihl` < 5) produces a huge $\ell$ and rejects by this rule; it is
never undefined behavior. Variable-length fields bind no numeric
value in $\rho$; W4 keeps them out of every expression.

### 4.4 Metadata assignment

Assigns run after the state's extracts, in declared order; each
truncates to its target's width:

$$
\dfrac{v = [\![ e ]\!]_{\rho,\mu,r}}
{\langle m \leftarrow e,\; \mu \rangle \;\Downarrow\;
\mu[m \mapsto v \bmod 2^{w_m}]}
\quad \text{(A-Assign)}
$$

where $r$ is `remaining()` at the state's entry region depth (W8
guarantees a region is open if $r$ is consulted). Assignment is total:
no failure mode, no effect on the cursor, the regions, or the budget.

### 4.5 Region push

Region ops run after assigns, in declared order. A push of $e$ bytes
at cursor $c$ (requires $8 \mid c$) checks *structurally only*
against the enclosing region — not against the input:

$$
\ell = [\![ e ]\!]_{\rho,\mu,\bot} \qquad
\mathit{end} = c + 8\ell \ \text{(overflow-checked)}
$$

$$
\dfrac{\mathit{end}\ \text{defined} \qquad
(R = \epsilon \;\lor\; \mathit{end} \le \mathrm{top}(R))}
{\langle \mathit{push}\ e,\; R \rangle \;\Downarrow\; R \cdot \mathit{end}}
\quad \text{(G-Push)}
$$

$$
\dfrac{\mathit{end}\ \text{undefined (overflow)} \;\lor\;
(R \ne \epsilon \;\land\; \mathit{end} > \mathrm{top}(R))}
{\langle \mathit{push}\ e,\; R \rangle \;\Downarrow\;
\mathbf{Reject}\langle \texttt{region out of bounds},\, c,\, \mu \rangle}
\quad \text{(G-Push-Lie)}
$$

A region reaching past the *input* is deliberately not a push-time
error: the declared length may be honest while the capture is short;
the reads it licenses will fail in the truncation class. A region
that cannot fit its *enclosing region* is a structural lie at the
moment it is declared.

### 4.6 Region pop (exact mode)

Pop closes the innermost region; the cursor must sit exactly at its
end:

$$
\dfrac{R = R' \cdot \mathit{end} \qquad c = \mathit{end}}
{\langle \mathit{pop},\; R \rangle \;\Downarrow\; R'}
\quad \text{(G-Pop)}
$$

$$
\dfrac{R = R' \cdot \mathit{end} \qquad c < \mathit{end} \qquad \mathit{end} > |\pi|}
{\langle \mathit{pop},\; R \rangle \;\Downarrow\;
\mathbf{Reject}\langle \texttt{out of bounds},\, c,\, \mu \rangle}
\quad \text{(G-Pop-Trunc)}
$$

$$
\dfrac{R = R' \cdot \mathit{end} \qquad c < \mathit{end} \qquad \mathit{end} \le |\pi|}
{\langle \mathit{pop},\; R \rangle \;\Downarrow\;
\mathbf{Reject}\langle \texttt{region not exhausted},\, c,\, \mu \rangle}
\quad \text{(G-Pop-Short)}
$$

$c > \mathit{end}$ is unreachable (reads never cross the region
end). The two shortfall classes mirror incumbent behavior: a region
end beyond the input with all inner content consistent is "need more
bytes" (truncation); a region end within the input means real
trailing content the program failed to consume (structural). W8 rules
out popping an empty stack.

### 4.7 Transition

After the region ops, the state takes its transition. A `direct`
transition yields its target. A `select` first evaluates its keys
left-to-right in the post-ops context ($r$ from the post-ops region
stack), then takes the **first** arm, in declared order, whose every
entry matches the corresponding key:

$$
\dfrac{k_j = [\![ e_j ]\!]_{\rho,\mu,r} \qquad
i = \min\{\, i \mid \forall j.\; k_j \models \mathit{entry}_{ij} \,\}}
{\langle \mathit{select},\; \sigma \rangle \;\Downarrow\; \mathit{target}_i}
\quad \text{(T-Arm)}
$$

If no arm matches and a default target is present, it is taken; if no
arm matches and there is no default:

$$
\dfrac{\forall i.\ \exists j.\ k_j \not\models \mathit{entry}_{ij}
\qquad \text{no default}}
{\langle \mathit{select},\; \sigma \rangle \;\Downarrow\;
\mathbf{Reject}\langle \texttt{no matching select arm},\, c,\, \mu \rangle}
\quad \text{(T-NoMatch)}
$$

Arm order is the priority order — overlapping keysets (masks, ranges)
are resolved by first match, never by specificity.

### 4.8 Targets

$$
\dfrac{\mathit{target} = \mathit{state}\ q'}
{\sigma \;\longrightarrow\; \langle q', c', \rho', \mu', R', d' \rangle}
\quad \text{(T-Goto)}
\qquad
\dfrac{\mathit{target} = \mathit{accept}}
{\sigma \;\longrightarrow\; \mathbf{Accept}\langle c', \mu' \rangle}
\quad \text{(T-Accept)}
$$

$$
\dfrac{\mathit{target} = \mathit{reject}(\mathit{reason})}
{\sigma \;\longrightarrow\;
\mathbf{Reject}\langle \mathit{reason},\, c',\, \mu' \rangle}
\quad \text{(T-Reject)}
$$

where primes denote the post-body values. An explicit reject carries
its authored reason. Its `severity` annotation (`"error"` default,
`"info"` marking a payload boundary) classifies the reject for
diagnostic consumers only; no rule reads it, and built-in rejects
(R-Depth, E-\*, G-\*, T-NoMatch) are always `"error"`-class.

Bits beyond the final cursor are the *payload*: unconsumed, and not
part of any observable.

## 5. Metatheory

**Theorem (totality/progress).** For every well-formed program and
every finite input $\pi$, every non-terminal configuration has
exactly one applicable rule; the machine never sticks. *Proof
sketch:* each phase's rules case-split exhaustively on decidable
conditions ($c + n$ vs. bounds, stack emptiness via W8, arm matching
is total); expression evaluation is total by W4/W5/W8 (no $\bot$
consulted) and W7 (no unbound reference); modular arithmetic has no
error case. The one caveat is the alignment fault of §2, which is an
error of the *program*, not of the run. ∎

**Theorem (termination/decidability).** Every run terminates after at
most $D$ state entries; consequently acceptance is decidable, and
every run consumes at most $\min(|\pi|,\ D \cdot W)$ bits where $W$
bounds one state's extraction. *Proof sketch:* R-Depth makes $d$
strictly increase on every machine step and terminates the run at $d
> D$; no rule decreases $d$ or modifies $D$. Termination is thus
independent of $\pi$, of the state graph's cycles, and of every
value computed — `max_depth` is the sole termination authority. ∎

**Corollary (symbolic finiteness).** The tree of feasible runs of a
well-formed program, branching over all inputs, has depth at most $D$
and finite branching (each select has finitely many arms plus a
default or T-NoMatch; each read has finitely many failure classes) —
hence finitely many path classes. This is the property the symbolic
executor enumerates and the reason exhaustive path enumeration is
possible by construction.

## 6. Conformance

An implementation conforms iff, for every well-formed IR program and
every input, it produces the same outcome, reject reason, consumed
length, final metadata, and extracted headers as this semantics. The
repository's test-vector format (`proto/pakeles/testvec/v1alpha1`)
serializes the core of these observables — on accept, the extracted
headers and final metadata; on reject, the reason — and the golden
suites under the benchmark and example galleries are the conformance
corpus. Consumed length and reject-time forensics (stop state,
instance, field, offset) are additional interpreter observables not
currently vectorized. Datapath backends that cannot report all
observables (e.g. an XDP program returning a verdict) conform on the
observables they expose.
