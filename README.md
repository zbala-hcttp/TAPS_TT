# TAPS_TT

TAPS with Threshold Tracing: a Rust implementation of a TAPS-style
accountable threshold signature (Boneh 2022) extended so that tracing is
performed by `n_3` tracers instead of a single trusted one.

## Protocol shape

- `n` signers, threshold `t = floor(n/2) + 1`, hold Schnorr key shares and
  jointly produce a signature via one combiner.
- `n_3` tracers, reconstruction threshold `t_e = floor(2*n_3/3) + 1`, hold no
  designated per-signer key. Instead they run a Feldman-style distributed key
  generation (`protocol::dkg`) to agree on one group public key `pk_e`; each
  tracer keeps a Shamir share `sk_{e_k}` of the matching secret.
- The combiner encrypts every signer's attendance bit `b_i` under `pk_e`,
  each with its own fresh randomness `gamma_i`, and proves in zero knowledge
  that the aggregate signature is consistent with the encrypted bits.
- Any `t_e` of the `n_3` tracers can cooperate to threshold-decrypt the
  attendance bits and the aggregate response, each publishing a partial
  decryption with a Chaum-Pedersen proof of correctness
  (`protocol::dkg::{partial_decrypt, combine_partial_decryptions}`), and
  recover the signing quorum without any tracer ever learning the others'
  key shares.

`n_3 = 1` is a valid, fully supported configuration: the DKG degenerates to
a single party holding the whole secret with `t_e = 1`, and the rest of the
protocol runs unchanged.

## Layout

- `src/protocol/taps_tt.rs` - the core signing/verification protocol: key
  pairs, commitments, the Schnorr signature, the ElGamal encryption of the
  aggregate response and attendance bits, and the Sigma-protocol
  accountability proof (`Blinds`, `Hats`, `Proofs`, `Statement`, `Sigma`).
- `src/protocol/dkg.rs` - the tracers' distributed key generation, Feldman
  verification, Chaum-Pedersen proofs, Lagrange recombination and quorum
  tracing.
- `src/protocol/field.rs`, `src/protocol/group.rs` - `Z_q` scalar and
  secp256k1 group-element arithmetic with an explicit identity element
  (`secp256k1::PublicKey` cannot represent `1_G`, which the DKG and
  threshold decryption both produce naturally).
- `src/protocol/dkg_hash.rs` - the domain-separated transcript hashing used
  by the DKG's proof of knowledge and the Chaum-Pedersen proofs.
- `src/protocol/test.rs` - unit and end-to-end tests, including full runs
  with 100 signers against both `n_3 = 1` and `n_3 = 5` tracers.

See `Simulation_TAPS_TT` (a sibling crate, depending on this one by path)
for a networked simulation of the whole protocol between separate Authority,
Combiner, Signer and Tracer processes.

## Running the tests

```
cargo test
```
