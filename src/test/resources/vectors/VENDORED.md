# Vendored test vectors

Verbatim copy of https://github.com/resolvingarchitecture/did-vectors
(DID DESIGN.md §2.3 / §10: every port ships the same vectors, copied not
submoduled). Do not hand-edit — regenerate upstream and re-copy:

    cp ../../../../did-vectors/{events.json,rotation.json,README.md} .

CC0-1.0.

## `nip44.json`

Different provenance from the files above: this is the **official NIP-44
spec's own test vector suite** (nostr-protocol, not RA's did-vectors),
fetched via a cached copy already present in this machine's Cargo registry
for the `nostr` crate (`nostr-0.45.4/src/nips/nip44/nip44.vectors.json`),
which vendors the same file the reference JS implementation
(`nostr-tools`) and other NIP-44 implementations test against. Do not
hand-edit. Public domain / spec-vector convention (no separate license
header in the upstream file).
