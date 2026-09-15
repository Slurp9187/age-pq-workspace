# Secret buffer growth, and why `with_secret_mut` is not a safe place to grow

Status: fixed at the two sites below in `0.2.0-rc.3`. The residual gap is
tracked here as [#43](https://github.com/Slurp9187/age-pq-workspace/issues/43)
and upstream as secure-gate issue #133; it is not closable in code today.

## The defect

A `Vec<u8>` or `String` that reallocates frees its old buffer **unwiped**. The
allocator gets back memory still holding whatever the buffer contained, and
nothing in `Drop` can reach it, because by the time `Drop` runs the old block
is long gone.

A secure-gate wrapper does not change this. `Dynamic<T>` zeroizes the
allocation it owns *at drop*. If the value inside it reallocated five times on
the way there, the wrapper wipes the fifth buffer and knows nothing about the
first four.

So the hazard is not "unwrapped secrets". It is **growth inside a wrapper**,
which reads as protected and is not.

## Where this workspace had it

Two sites, both filling a zero-capacity buffer through `with_secret_mut`.

### `age-plugin-pq/src/main.rs` — the plugin's stdin read

```rust
let mut input = SecretText::new(String::new());          // capacity 0
input.with_secret_mut(|buf| io::stdin().read_to_string(buf))?;
```

This is `convert_native_identities`, which reads `AGE-SECRET-KEY-PQ-` bech32
strings — **private keys** — from stdin. `read_to_string` grows from nothing,
so the residue scaled with the number of keys piped: convert a file of 500
identities and every growth left an unwiped copy of everything read so far.

CLAUDE.md's Tier-2 boundary inventory listed this site as a correct **Tier 1**
for several releases, on the reasoning that the read happened inside
`with_secret_mut`. That reasoning was exactly backwards: being inside the
closure is what let the caller reach `Vec`'s realloc.

### `age-pq-hpke/src/hpke.rs` — one-stage HPKE key schedule

```rust
let mut secrets = OneStageSecrets::new(Vec::new());      // capacity 0
secrets.with_secret_mut(|b| { /* extend_from_slice … shared_secret */ });
```

Smaller and bounded — three `extend_from_slice` calls, so at most a couple of
reallocs — but the bytes are the HPKE shared secret.

## The fixes

**`hpke.rs`: size the buffer.** The serialized length is known before the fill
(`len(psk) || len(ss) || ss`, so `2 * size_of::<u16>() + shared_secret.len()`),
so `Vec::with_capacity` makes growth impossible rather than merely unlikely.
This is what `labeled_extract` in `kdf.rs` already did, and it is the pattern
to copy.

**`main.rs`: fill through `io::Write`.** secure-gate implements
`std::io::Write` for `Dynamic<Vec<u8>>` (`src/dynamic.rs:777` at
`0.9.0-rc.9`), and that impl grows *by hand*:

```rust
let mut grown = Vec::with_capacity(new_cap);
grown.extend_from_slice(v);
v.zeroize();        // contents AND spare capacity, len → 0, no free
*v = grown;         // the zeroed allocation drops here
```

It mirrors `Vec`'s amortized doubling, so repeated writes stay linear. It is
the only growth path in the crate that wipes what it abandons.

`Dynamic<String>` has **no** `Write` impl, and no sized constructor can help
here either — stdin's length is not known in advance. So the site moves to a
byte wrapper and validates UTF-8 on the way out:

```rust
let mut input = SecretBytes::new(Vec::new());
io::copy(&mut io::stdin(), &mut input)?;
input.with_secret(|bytes| {
    let input = std::str::from_utf8(bytes).map_err(…)?;
    …
})
```

Bech32 is ASCII, so this costs nothing semantically. Validation stays
whole-buffer rather than per-line, matching `read_to_string`'s behaviour
exactly: a malformed line is already fatal further down, so per-line validation
would buy nothing and would be a silent semantic change in a security tool.

## What the fix does not do

**It is not zero-residue, and should not be described as if it were.** Two
buffers still see plaintext and neither is reachable from this workspace:

- `io::copy`'s own transfer buffer (8 KiB, stack, not wiped).
- `Stdin`'s internal `BufReader`, which is process-global, heap-allocated, and
  lives until exit. `read_to_string` had this too, so moving does not regress
  it — but it means the keys are still in process memory after the read.

Reading fd 0 directly to avoid the second would require `unsafe`, which
`#![forbid(unsafe_code)]` rules out workspace-wide.

What the fix removes is the **unbounded chain that scales with input size**.
That is the part that made this a defect rather than a fixed-size residue, and
it is the framing to use when describing it: "N keys piped left N copies" is
the fact that makes the priority obvious, where "unwiped realloc" reads as
theoretical.

## The general rule

Fill a growable wrapper through `Write`, or size it exactly before
construction. Never grow one from inside `with_secret_mut`.

`with_secret_mut` is a third door to the same hazard as an unsized
constructor. Anything that can reallocate — `extend_from_slice`, `push`,
`read_to_string`, `write!` — is unsafe there unless capacity was reserved
exactly, before the wrapper existed.

## Upstream

secure-gate issue #133 tracks the residual gap: caller-driven mutation through
`with_secret_mut` hands out `&mut Vec<u8>`, and that reallocation is outside
the crate's control. It **cannot** be closed in code today — stable Rust offers
no hook between "logically dead" and "returned to the allocator", and
`forbid(unsafe_code)` rules out the alternatives. The `Dynamic<Vec<u8>>`
`Write` impl's own doc comment already scoped its guarantee to "the buffer this
impl owns" and pointed at the same gap; this workspace walked through the
undocumented side of that boundary.

Related: a fourth exit from wrapper protection, invisible to a grep for either
`expose_secret` or `into_inner`, is `with_secret_mut(core::mem::take)` — it
moves the value out and leaves the wrapper holding an empty `Vec` that
zeroizes nothing. `age-pq-hpke/src/kdf.rs` uses it deliberately at four sites
(the internal `Kdf` trait returns `Vec<u8>` by design and callers re-wrap
immediately), but it belongs in the same audit sweep as the other two.
