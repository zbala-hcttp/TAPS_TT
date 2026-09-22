use rand::seq::SliceRandom;
use rand::{RngCore, thread_rng};
use secp256k1::{Error, PublicKey, Scalar, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// Helper module for serializing/deserializing Scalars
mod serde_scalar {
    use secp256k1::Scalar;
    use serde::{Deserialize, Deserializer, Serializer, Serialize}; // Added Serialize trait

    // Serialize a single Scalar
    pub fn serialize<S>(scalar: &Scalar, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // OLD (Broken): serializer.serialize_bytes(...) -> Adds 8-byte length prefix!

        // NEW (Fixed): Serialize as a fixed [u8; 32] array.
        // Bincode writes this as 32 raw bytes (No length prefix).
        let bytes = scalar.to_be_bytes();
        bytes.serialize(serializer)
    }

    // Deserialize a single Scalar
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Scalar, D::Error>
    where
        D: Deserializer<'de>,
    {
        // This expects 32 raw bytes (matches the fixed writer above)
        let bytes: [u8; 32] = Deserialize::deserialize(deserializer)?;
        Scalar::from_be_bytes(bytes).map_err(serde::de::Error::custom)
    }

    // --- Helper for Vec<Scalar> ---
    // This part was actually fine, but let's make it consistent.
    pub mod vec {
        use super::*;
        use serde::ser::SerializeSeq;

        pub fn serialize<S>(vec: &Vec<Scalar>, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut seq = serializer.serialize_seq(Some(vec.len()))?;
            for element in vec {
                // Wrap the bytes so they serialize as a fixed array, not a slice
                seq.serialize_element(&element.to_be_bytes())?;
            }
            seq.end()
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Scalar>, D::Error>
        where
            D: Deserializer<'de>,
        {
            let bytes_vec: Vec<[u8; 32]> = Deserialize::deserialize(deserializer)?;
            let mut scalars = Vec::with_capacity(bytes_vec.len());
            for bytes in bytes_vec {
                let s = Scalar::from_be_bytes(bytes).map_err(serde::de::Error::custom)?;
                scalars.push(s);
            }
            Ok(scalars)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPair {
    pub(crate) sk: SecretKey,
    pub(crate) pk: PublicKey,
}

impl KeyPair {
    pub fn create() -> Self {
        let secp = Secp256k1::new();
        let (sk, pk) = secp.generate_keypair(&mut secp256k1::rand::rng());

        KeyPair { sk, pk }
    }

    pub fn from_secret(secret_bytes: &[u8; 32]) -> Result<Self, secp256k1::Error> {
        let secp = Secp256k1::new();

        let sk = SecretKey::from_byte_array(*secret_bytes)?;
        let pk = PublicKey::from_secret_key(&secp, &sk);

        Ok(KeyPair { sk, pk })
    }
}

/// Holds only the Public Keys (h_i) of the tracing scheme.
/// Used by Signers and Combiner to encrypt their status, but not decrypt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracingKeys {
    pub(crate) tks: Vec<PublicKey>,
}

impl TracingKeys {
    /// Creates a TracingKeys struct from a list of full KeyPairs.
    /// Extracts only the Public Key (pk) from each KeyPair.
    pub fn set(kps: &[KeyPair]) -> Self {
        let tks = kps.iter().map(|kp| kp.pk).collect();

        TracingKeys { tks }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Quorum {
    pub(crate) participants: Vec<(PublicKey, u8)>,
}

impl Quorum {
    pub fn choose(n: usize, t: usize, all_signers: &[KeyPair]) -> Self {
        assert_eq!(
            all_signers.len(),
            n,
            "Input signer list length must match n"
        );
        assert!(t <= n, "Threshold t cannot be larger than n");

        let mut indices: Vec<usize> = (0..n).collect();
        let mut rng = thread_rng();

        indices.shuffle(&mut rng);

        let mut attendance = vec![0u8; n];
        for &idx in indices.iter().take(t) {
            attendance[idx] = 1;
        }

        // 3. Construct the result vector (Preserving original order of signers)
        let mut result_vec = Vec::with_capacity(n);

        for (i, signer_kp) in all_signers.iter().enumerate() {
            // We use the getter .public_key() we added earlier
            let pk = signer_kp.pk;
            let bit = attendance[i];

            result_vec.push((pk, bit));
        }

        Quorum {
            participants: result_vec,
        }
    }

    pub fn set(pubkeys: &PK, attendance_bits: &[u8]) -> Self {
        let all_signers = pubkeys.pk_i.clone();
        assert_eq!(
            all_signers.len(),
            attendance_bits.len(),
            "Signer list and attendance bits must have the same length"
        );

        let mut result_vec = Vec::with_capacity(all_signers.len());

        for (signer_kp, &bit) in all_signers.iter().zip(attendance_bits.iter()) {
            result_vec.push((*signer_kp, bit));
        }

        Quorum {
            participants: result_vec,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sign {
    #[serde(with = "serde_scalar")]
    pub(crate) z: Scalar,
}

impl Sign {
    pub fn sign(comm: &Commit, keys: &KeyPair, c: &Scalar) -> Sign {
        let mut term_sk_c = keys.sk;

        term_sk_c = term_sk_c
            .mul_tweak(c)
            .expect("Sign failed: mul_tweak invalid (sk * c)");

        let r_secret = comm.nonce.sk;
        let r_scalar = Scalar::from_be_bytes(r_secret.secret_bytes())
            .expect("Sign failed: r_i invalid scalar");

        let z_key = term_sk_c
            .add_tweak(&r_scalar)
            .expect("Sign failed: add_tweak invalid (sk*c + r)");

        Sign {
            z: Scalar::from_be_bytes(z_key.secret_bytes())
                .expect("Sign failed: Final z scalar conversion"),
        }
    }

    pub fn aggregate(shares: &[Sign], quo: &Quorum) -> Sign {
        assert_eq!(
            shares.len(),
            quo.participants.len(),
            "Shares and Quorum participants must have the same length"
        );

        // 1. Filter valid shares based on the Quorum bits
        let valid_scalars: Vec<&Scalar> = shares
            .iter()
            .zip(quo.participants.iter())
            .filter_map(|(sign_struct, (_pk, bit))| {
                if *bit == 1 {
                    Some(&sign_struct.z)
                } else {
                    None
                }
            })
            .collect();

        // 2. Handle empty case (no one signed)
        if valid_scalars.is_empty() {
            return Sign {
                z: Scalar::from_be_bytes([0u8; 32]).unwrap(),
            };
        }

        // 3. Sum the scalars
        let mut sum_sk = SecretKey::from_byte_array(valid_scalars[0].to_be_bytes())
            .expect("Invalid scalar share");

        for scalar_share in valid_scalars.iter().skip(1) {
            sum_sk = sum_sk
                .add_tweak(scalar_share)
                .expect("Scalar addition failed during aggregation");
        }

        Sign {
            z: Scalar::from_be_bytes(sum_sk.secret_bytes())
                .expect("Final scalar conversion failed"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Commit {
    pub(crate) nonce: KeyPair,
}

impl Commit {
    pub fn commit() -> Self {
        Commit {
            nonce: KeyPair::create(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Commitment {
    pub(crate) R: PublicKey,
}

impl Commitment {
    pub fn set(commit: &Commit) -> Self {
        Commitment { R: commit.nonce.pk }
    }

    pub fn aggregate(commitments: &[Commitment], quo: &Quorum) -> Result<PublicKey, Error> {
        assert_eq!(
            commitments.len(),
            quo.participants.len(),
            "Commitments and Quorum participants must have the same length"
        );

        // 1. Filter valid commitments based on Quorum bits
        let valid_pubkeys: Vec<PublicKey> = commitments
            .iter()
            .zip(quo.participants.iter())
            .filter_map(|(comm, (_pk, bit))| {
                if *bit == 1 {
                    // Access the public key of the nonce
                    Some(comm.R)
                } else {
                    None
                }
            })
            .collect();

        // 2. Handle empty case (no one participated)
        if valid_pubkeys.is_empty() {
            return Err(Error::InvalidPublicKey); // Cannot aggregate 0 keys into a valid Point
        }

        // 3. Aggregate Public Keys (Point Addition)
        let mut R_agg = valid_pubkeys[0];

        for next_key in valid_pubkeys.iter().skip(1) {
            R_agg = R_agg.combine(next_key)?;
        }

        Ok(R_agg)
    }
}

/*pub fn get_second_generator_h() -> PublicKey {
    // Start with a fixed, agreed-upon seed string
    let mut seed = b"TAPS_SECONDARY_GENERATOR".to_vec();

    loop {
        // 1. Hash the seed
        let mut hasher = Sha256::new();
        hasher.update(&seed);
        let hash = hasher.finalize();

        // 2. Try to interpret hash as a compressed public key (prepend 0x02 for even Y)
        let mut candidate_bytes = vec![0x02u8];
        candidate_bytes.extend_from_slice(&hash);

        // 3. Check if valid curve point
        if let Ok(point) = PublicKey::from_slice(&candidate_bytes) {
            return point;
        }

        // 4. If invalid, re-hash the result and try again
        // This creates a deterministic chain until a valid point is found.
        let mut rehasher = Sha256::new();
        rehasher.update(&seed); // Mistake in previous snippet fixed here: hash the previous output?
        // Actually, your snippet re-hashed the 'seed' again which was effectively
        // re-hashing the PREVIOUS hash if we update 'seed'.
        // Let's simplify to match your logic:

        seed = hash.to_vec(); // Update seed to be the current hash for next iteration
    }
}
*/

pub fn get_second_generator_h() -> PublicKey {
    let mut counter: u32 = 0;
    loop {
        let mut hasher = Sha256::new();
        hasher.update(b"TAPS/second-generator/v1");   // domain-separated tag
        hasher.update(&counter.to_be_bytes());          // vary the input each try
        let x = hasher.finalize();

        // try even-Y (0x02) then odd-Y (0x03)
        for prefix in [0x02u8, 0x03u8] {
            let mut candidate = Vec::with_capacity(33);
            candidate.push(prefix);
            candidate.extend_from_slice(&x);
            if let Ok(p) = PublicKey::from_slice(&candidate) {
                return p;
            }
        }
        counter += 1;   // ~50% success per counter, so this terminates fast
    }
}

#[derive(Debug, Clone)]
pub struct Secret {
    pub(crate) s: Scalar,
}

impl Secret {
    /// Generates a random secret scalar.
    pub fn create() -> Self {
        let mut rng = thread_rng();
        let mut bytes = [0u8; 32];

        loop {
            // 1. Fill 32 bytes with random data
            rng.fill_bytes(&mut bytes);

            // 2. Try to convert to a valid SecretKey (which ensures it's < Curve Order)
            // We use SecretKey here just for the validation logic,
            // but we don't compute the Public Key.
            if let Ok(sk) = SecretKey::from_byte_array(bytes) {
                return Secret {
                    s: Scalar::from_be_bytes(sk.secret_bytes()).unwrap(),
                };
            }
            // If invalid (extremely rare), loop and try again.
        }
    }
}

pub fn encrypt_bits(sec: &Secret, quo: &Quorum, kps: &TracingKeys) -> (PublicKey, Vec<PublicKey>) {
    let secp = Secp256k1::new();
    assert_eq!(
        quo.participants.len(),
        kps.tks.len(),
        "Mismatch between quorum size and keys provided"
    );

    // 1. Compute v0 = g^r
    // Convert 'r' to SecretKey for operation
    let r_sk = SecretKey::from_byte_array(sec.s.to_be_bytes()).unwrap();
    let v0 = PublicKey::from_secret_key(&secp, &r_sk);

    // 2. Compute v_i for each participant
    let mut v_vec = Vec::with_capacity(kps.tks.len());

    for (i, (_pk, bit)) in quo.participants.iter().enumerate() {
        // A. Compute shared secret term: S = pk_i^r (which is r * pk_i)
        // We take the i-th public key
        let pk_i = kps.tks[i]; // Or kps[i].public_key()

        let shared_secret = pk_i
            .mul_tweak(&secp, &sec.s)
            .expect("Failed to compute pk^r");

        // B. Compute v_i based on the bit
        if *bit == 1 {
            // Case 1: v_i = g^1 * pk^r = G + shared_secret

            // We generate G by taking the public key of '1'
            // (Alternatively, use the library's generator constant if available,
            // but creating it from scalar 1 is generic and safe).
            let one_sk = SecretKey::from_byte_array([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 1,
            ])
                .unwrap();
            let G = PublicKey::from_secret_key(&secp, &one_sk);

            // Add G to shared secret
            let v_i = G.combine(&shared_secret).expect("Point addition failed");
            v_vec.push(v_i);
        } else {
            // Case 0: v_i = g^0 * pk^r = Infinity + shared_secret = shared_secret
            // We just push the shared secret directly.
            v_vec.push(shared_secret);
        }
    }

    (v0, v_vec)
}

/// Decrypts the vector of commitments v_i to recover the original bits b_i.
///
/// Inputs:
/// - v0: The ephemeral public key (g^r).
/// - v_vec: The vector of encrypted bits (v_i).
/// - tracing_keys: The Tracer's KeyPairs (containing private key tau_i).
///
/// Logic:
/// 1. Compute shared secret S = v0^tau_i
/// 2. If v_i == S, then g^b_i must be 1 (Identity), so b_i = 0.
/// 3. If v_i == S + G, then g^b_i must be G, so b_i = 1.
pub fn decrypt_bits(
    v0: &PublicKey,
    v_vec: &[PublicKey],
    tracing_keys: &[KeyPair],
) -> Result<Vec<u8>, String> {
    let secp = Secp256k1::new();

    if v_vec.len() != tracing_keys.len() {
        return Err("Mismatch between ciphertext vector and tracing keys".to_string());
    }

    // Pre-compute Generator G (g^1)
    let one_sk = SecretKey::from_byte_array([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1,
    ])
        .unwrap();
    let G = PublicKey::from_secret_key(&secp, &one_sk);

    let mut decrypted_bits = Vec::with_capacity(v_vec.len());

    for (i, v_i) in v_vec.iter().enumerate() {
        // 1. Get the private tracing key (tau_i)
        let tau_i = tracing_keys[i].sk;

        // 2. Compute shared secret term: S = v0^tau_i
        let shared_secret = v0
            .mul_tweak(&secp, &Scalar::from_be_bytes(tau_i.secret_bytes()).unwrap())
            .map_err(|_| "Failed to compute v0^tau_i")?;

        // 3. Check Case 0: Is v_i == S?
        // If yes, then v_i = v0^tau_i * g^0, so bit is 0.
        if *v_i == shared_secret {
            decrypted_bits.push(0);
        }
        // 4. Check Case 1: Is v_i == S + G?
        // If yes, then v_i = v0^tau_i * g^1, so bit is 1.
        else {
            let candidate_one = shared_secret
                .combine(&G)
                .map_err(|_| "Failed to combine shared_secret with G")?;

            if *v_i == candidate_one {
                decrypted_bits.push(1);
            } else {
                // If neither, the ciphertext is invalid or corrupted
                return Err(format!(
                    "Decryption failed at index {}: Value is neither 0 nor 1",
                    i
                ));
            }
        }
    }

    Ok(decrypted_bits)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ElGamalCiphertext {
    pub c0: PublicKey, // Randomness (r * G)
    pub c1: PublicKey, // Message + Mask (m * G + r * H)
}

impl ElGamalCiphertext {
    pub fn encrypt(sec: &Secret, message: &Sign, kp: &PK) -> Self {
        let secp = Secp256k1::new();

        // 1. Convert Secrets to SecretKeys for math operations
        let r_sk = SecretKey::from_byte_array(sec.s.to_be_bytes()).unwrap();
        let m_sk = SecretKey::from_byte_array(message.z.to_be_bytes()).unwrap();

        // 2. Compute c0 = g^r
        // (PublicKey from SecretKey is technically g^sk)
        let c0 = PublicKey::from_secret_key(&secp, &r_sk);

        // 3. Compute c1 = g^m * P^r

        // 3a. Term 1: g^m
        let g_m = PublicKey::from_secret_key(&secp, &m_sk);

        // 3b. Term 2: P^r
        // We multiply the recipient's Public Key (P) by the scalar (r)
        let P = kp.pk_t;
        let P_r = P
            .mul_tweak(&secp, &sec.s)
            .expect("ElGamal encryption failed: P^r invalid");

        // 3c. Combine: c1 = g^m + P^r (Elliptic Curve Addition)
        let c1 = g_m.combine(&P_r).expect("Point addition failed");

        ElGamalCiphertext { c0, c1 }
    }

    pub fn encrypt_value(sec: &Secret, t: &Scalar) -> Self {
        let secp = Secp256k1::new();

        // 1. Compute c0 = g^sec (r * G)
        let r_sk = SecretKey::from_byte_array(sec.s.to_be_bytes()).unwrap();
        let c0 = PublicKey::from_secret_key(&secp, &r_sk);

        // 2. Compute c1 = g^t * h^sec

        // A. Term 1: g^t (t * G)
        // We treat 't' as a SecretKey to multiply it by the standard generator G
        let t_sk = SecretKey::from_byte_array(t.to_be_bytes()).expect("Invalid scalar t");
        let g_t = PublicKey::from_secret_key(&secp, &t_sk);

        // B. Term 2: h^sec (sec * H)
        let h = get_second_generator_h();
        let h_r = h.mul_tweak(&secp, &sec.s).expect("Failed to compute h^sec");

        // C. Combine: c1 = g_t + h_r
        let c1 = g_t.combine(&h_r).expect("Point addition failed");

        ElGamalCiphertext { c0, c1 }
    }

    pub fn decrypt(cipher: &ElGamalCiphertext, kp: &KeyPair) -> PublicKey {
        let secp = Secp256k1::new();

        // 1. Negate the Secret Key directly
        // The SecretKey struct has a standard helper for this.
        let neg_sk_key = kp.sk.negate();

        // 2. Convert the negated key to a Scalar
        // This is safe because if 's' is a valid key, 'n - s' is also valid.
        let neg_sk_scalar =
            Scalar::from_be_bytes(neg_sk_key.secret_bytes()).expect("Invalid negated scalar");

        // 3. Compute -S = c0 * (-sk)
        let neg_S = cipher
            .c0
            .mul_tweak(&secp, &neg_sk_scalar)
            .expect("Decryption failed: Invalid point multiplication");

        // 4. Combine: c1 + (-S)
        cipher
            .c1
            .combine(&neg_S)
            .expect("Decryption failed: Point addition error")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PK {
    pub(crate) pk_i: Vec<PublicKey>,
    pub(crate) pk_cs: PublicKey,
    pub(crate) pk_t: PublicKey,
}

impl PK {
    /// Sets up the Registry using a complete Ciphertext object.
    pub fn set(kps: &[KeyPair], kp_cs: &KeyPair, kp_t: &KeyPair) -> Self {
        let signers_pks: Vec<PublicKey> = kps.iter().map(|kp| kp.pk).collect();

        PK {
            pk_i: signers_pks,
            pk_cs: kp_cs.pk,
            pk_t: kp_t.pk,
        }
    }
}

/// Maps an arbitrary byte string onto a non-zero scalar of the secp256k1 group.
///
/// `Sha256` output is only *almost* a uniform scalar: it can land on zero or on a
/// value >= the group order. Both are rejected and the counter is bumped, so this
/// never panics and never returns zero (which would collapse the terms it is used in).
fn hash_to_scalar(tag: &[u8], data: &[u8]) -> Scalar {
    let mut counter: u32 = 0;
    loop {
        let mut hasher = Sha256::new();
        hasher.update(tag);
        hasher.update(&counter.to_be_bytes());
        hasher.update(data);
        let digest: [u8; 32] = hasher.finalize().into();

        if let Ok(s) = Scalar::from_be_bytes(digest) {
            if s != Scalar::ZERO {
                return s;
            }
        }
        counter += 1;
    }
}

/// Absorbs the public parameters that every challenge in the protocol is bound to.
/// Vectors are length-prefixed so that no two distinct parameter sets can produce
/// the same byte stream.
fn absorb_params(hasher: &mut Sha256, pk: &PK, tks: &TracingKeys) {
    hasher.update(&(pk.pk_i.len() as u64).to_be_bytes());
    for signer_pk in &pk.pk_i {
        hasher.update(&signer_pk.serialize());
    }
    hasher.update(&pk.pk_cs.serialize());
    hasher.update(&pk.pk_t.serialize());

    hasher.update(&(tks.tks.len() as u64).to_be_bytes());
    for h_i in &tks.tks {
        hasher.update(&h_i.serialize());
    }
}

/// The Schnorr challenge `c = H(params || T || R || m)`.
///
/// This is the only challenge the signers need, and it is derived before the
/// combiner has produced any of the tracing material, so it deliberately covers
/// just the public parameters, the encrypted threshold `T`, the aggregate nonce
/// `R` and the message.
pub fn compute_challenge_c(
    pk: &PK,
    tks: &TracingKeys,
    T: &ElGamalCiphertext,
    R: &PublicKey,
    m: &[u8],
) -> Scalar {
    let mut hasher = Sha256::new();
    absorb_params(&mut hasher, pk, tks);
    hasher.update(&T.c0.serialize());
    hasher.update(&T.c1.serialize());
    hasher.update(&R.serialize());
    hasher.update(&(m.len() as u64).to_be_bytes());
    hasher.update(m);

    hash_to_scalar(b"TAPS/challenge-c/v1", &hasher.finalize())
}

/// The public statement the accountability proof is about.
///
/// Bundling it keeps prover and verifier hashing byte-for-byte the same
/// transcript, which is what makes the Fiat-Shamir challenges below binding.
#[derive(Clone, Copy)]
pub struct Statement<'a> {
    /// Signer / combiner / tracer public keys.
    pub pk: &'a PK,
    /// Public tracing keys h_i.
    pub tks: &'a TracingKeys,
    /// ElGamal encryption of the threshold t.
    pub T: &'a ElGamalCiphertext,
    /// Aggregate Schnorr nonce.
    pub R: &'a PublicKey,
    /// Signed message.
    pub m: &'a [u8],
    /// ElGamal encryption of the aggregate response z, under pk_t.
    pub ct: &'a ElGamalCiphertext,
    /// g^gamma, the ephemeral key of the encrypted quorum bits.
    pub v0: &'a PublicKey,
    /// Encrypted quorum bits v_i.
    pub v: &'a [PublicKey],
}

impl<'a> Statement<'a> {
    /// Re-derives the Schnorr challenge from the statement.
    pub fn c(&self) -> Scalar {
        compute_challenge_c(self.pk, self.tks, self.T, self.R, self.m)
    }

    /// Digest over the whole statement. Both `alpha` and `beta` start from it.
    fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        absorb_params(&mut hasher, self.pk, self.tks);
        hasher.update(&self.T.c0.serialize());
        hasher.update(&self.T.c1.serialize());
        hasher.update(&self.R.serialize());
        hasher.update(&(self.m.len() as u64).to_be_bytes());
        hasher.update(self.m);
        hasher.update(&self.ct.c0.serialize());
        hasher.update(&self.ct.c1.serialize());
        hasher.update(&self.v0.serialize());
        hasher.update(&(self.v.len() as u64).to_be_bytes());
        for v_i in self.v {
            hasher.update(&v_i.serialize());
        }
        hasher.finalize().into()
    }

    /// The batching challenge `alpha`.
    ///
    /// It folds the n per-bit "b_i is a bit" checks into the single S4c equation,
    /// so it MUST be drawn after the ciphertexts v_i are fixed - otherwise the
    /// prover can pick v_i to satisfy the batched equation with b_i outside {0,1}.
    pub fn alpha(&self, c: &Scalar) -> Scalar {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&self.digest());
        buf.extend_from_slice(&c.to_be_bytes());

        hash_to_scalar(b"TAPS/alpha/v1", &buf)
    }

    /// The Sigma-protocol challenge `beta`.
    ///
    /// It MUST commit to the prover's first-round commitments S1..S4c. If it does
    /// not, the responses can be chosen first and the commitments solved for
    /// afterwards, which forges the proof outright.
    pub fn beta(&self, alpha: &Scalar, proofs: &Proofs) -> Scalar {
        let mut hasher = Sha256::new();
        hasher.update(&self.digest());
        hasher.update(&alpha.to_be_bytes());
        hasher.update(&proofs.S1.serialize());
        hasher.update(&proofs.S2a.serialize());
        hasher.update(&proofs.S2b.serialize());
        hasher.update(&proofs.S3a.serialize());
        hasher.update(&proofs.S3b.serialize());
        hasher.update(&proofs.S4a.serialize());
        hasher.update(&(proofs.S4bi.len() as u64).to_be_bytes());
        for s in &proofs.S4bi {
            hasher.update(&s.serialize());
        }
        hasher.update(&proofs.S4c.serialize());

        hash_to_scalar(b"TAPS/beta/v1", &hasher.finalize())
    }
}

pub struct Phis {
    pub(crate) phis: Vec<Secret>,
}

impl Phis {
    /// Computes phi_i for every participant.
    /// phi_i = alpha^i+1 * gamma * (1 - b_i)
    pub fn set(alpha: &Scalar, gamma_scalar: &Secret, quo: &Quorum) -> Self {
        let mut phi_vec = Vec::with_capacity(quo.participants.len());

        // We start with alpha^1 = alpha.
        // In secp256k1, we can represent "1" as a byte array.
        let mut current_alpha_power_sk =
            SecretKey::from_byte_array(alpha.to_be_bytes()).expect("Invalid alpha scalar");

        // We need gamma as a SecretKey to perform multiplication
        let gamma =
            SecretKey::from_byte_array(gamma_scalar.s.to_be_bytes()).expect("Invalid alpha scalar");

        for (_pk, bit) in &quo.participants {
            // Formula: phi_i = (alpha^i * gamma) * (1 - bit)

            if *bit == 1 {
                // If bit is 1, term is (1 - 1) = 0.
                // Result is Scalar Zero.
                phi_vec.push(Secret {
                    s: Scalar::from_be_bytes([0u8; 32]).unwrap(),
                });
            } else {
                // If bit is 0, term is (1 - 0) = 1.
                // Result is alpha^i * gamma.

                // We convert current_alpha_power to Scalar so we can use it to tweak gamma
                let alpha_pow_scalar = Scalar::from_be_bytes(current_alpha_power_sk.secret_bytes())
                    .expect("Invalid alpha power scalar");

                // Calculate: gamma * alpha^i
                // We take 'gamma' and multiply it by the scalar 'alpha^i'
                let phi_val = gamma
                    .mul_tweak(&alpha_pow_scalar)
                    .expect("Calculation of phi_i failed");

                phi_vec.push(Secret {
                    s: Scalar::from_be_bytes(phi_val.secret_bytes()).unwrap(),
                });
            }

            // --- Prepare Alpha for next iteration ---
            // alpha^{i+1} = alpha^i * alpha
            // We update our running power accumulator.
            current_alpha_power_sk = current_alpha_power_sk
                .mul_tweak(alpha)
                .expect("Updating alpha power failed");
        }

        Phis { phis: phi_vec }
    }
}

#[derive(Debug, Clone)]
pub struct Witnesses {
    pub(crate) z: Scalar,
    pub(crate) rho: Scalar,
    pub(crate) gamma: Scalar,
    pub(crate) psi: Scalar,
    pub(crate) b_i: Vec<u8>,
    pub(crate) phi_i: Vec<Scalar>,
}

impl Witnesses {
    /// Constructs Witnesses by extracting data from Quorum and Phis.
    ///
    /// - quo: We extract bits b_i from quo.participants[i].1
    /// - phis: We extract the vector of scalars from phis.vec
    pub fn set(
        z: Sign,
        rho: Secret,
        gamma: Secret,
        psi: Secret,
        quo: &Quorum,
        phis: &Phis,
    ) -> Self {
        // 1. Extract bits b_i from the Quorum
        // quo.participants is Vec<(PublicKey, u8)>
        // We want a Vec<u8> containing just the second element (the bit)
        let b_i: Vec<u8> = quo.participants.iter().map(|(_, bit)| *bit).collect();

        // 2. Extract scalars phi_i from the Phis struct
        let phi_i = phis.phis.iter().map(|phi_| phi_.s).collect();

        Witnesses {
            z: z.z,
            rho: rho.s,
            gamma: gamma.s,
            psi: psi.s,
            b_i,
            phi_i,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Blinds {
    pub(crate) k_z: Secret,
    pub(crate) k_rho: Secret,
    pub(crate) k_gamma: Secret,
    pub(crate) k_psi: Secret,
    pub(crate) k_b_i: Vec<Secret>,
    pub(crate) k_phi_i: Vec<Secret>,
}

impl Blinds {
    /// Generates random blinding factors (secrets) for all protocol witnesses.
    /// 'n' is the number of participants in the quorum.
    pub fn set(n: usize) -> Self {
        // 1. Generate fixed scalars
        let k_z = Secret::create();
        let k_rho = Secret::create();
        let k_gamma = Secret::create();
        let k_psi = Secret::create();

        // 2. Generate vectors of secrets
        // We need 'n' secrets for the bits and 'n' secrets for the phi values.

        let mut k_b_i = Vec::with_capacity(n);
        let mut k_phi_i = Vec::with_capacity(n);

        for _ in 0..n {
            k_b_i.push(Secret::create());
            k_phi_i.push(Secret::create());
        }

        Blinds {
            k_z,
            k_rho,
            k_gamma,
            k_psi,
            k_b_i,
            k_phi_i,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hats {
    #[serde(with = "serde_scalar")]
    pub z_hat: Scalar,
    #[serde(with = "serde_scalar")]
    pub rho_hat: Scalar,
    #[serde(with = "serde_scalar")]
    pub gamma_hat: Scalar,
    #[serde(with = "serde_scalar")]
    pub psi_hat: Scalar,
    #[serde(with = "serde_scalar::vec")]
    pub b_hat: Vec<Scalar>,
    #[serde(with = "serde_scalar::vec")]
    pub phi_hat: Vec<Scalar>,
}

impl Hats {
    pub fn set(beta: &Scalar, witt: &Witnesses, bli: &Blinds) -> Self {
        // Helper: Computes (witness * beta) + blind
        let compute_response = |witness: &Scalar, blind: &Scalar| -> Scalar {
            // Case A: If witness is 0, the term (witness * beta) is 0.
            if *witness == Scalar::ZERO {
                return *blind;
            }

            // Case B: Compute (witness * beta) + blind

            // 1. Create a Mutable SecretKey from the witness
            let mut sk =
                SecretKey::from_byte_array(witness.to_be_bytes()).expect("Witness scalar invalid");

            // 2. Multiply: sk = sk * beta
            // USING ASSIGNMENT SYNTAX AS REQUESTED
            sk = sk.mul_tweak(beta).expect("Multiplication failed");

            // 3. Add: sk = sk + blind
            // USING ASSIGNMENT SYNTAX AS REQUESTED
            sk = sk.add_tweak(blind).expect("Addition failed");

            // 4. Return as Scalar
            Scalar::from_be_bytes(sk.secret_bytes()).unwrap()
        };

        // --- Compute Fixed Hats ---
        let z_hat = compute_response(&witt.z, &bli.k_z.s);
        let rho_hat = compute_response(&witt.rho, &bli.k_rho.s);
        let gamma_hat = compute_response(&witt.gamma, &bli.k_gamma.s);
        let psi_hat = compute_response(&witt.psi, &bli.k_psi.s);

        // --- Compute (b_i)_hat ---
        let mut b_hat = Vec::with_capacity(witt.b_i.len());
        for (i, &bit) in witt.b_i.iter().enumerate() {
            // Convert bit to Scalar
            let w_bit = if bit == 1 { Scalar::ONE } else { Scalar::ZERO };

            let val = compute_response(&w_bit, &bli.k_b_i[i].s);
            b_hat.push(val);
        }

        // --- Compute (phi_i)_hat ---
        let mut phi_hat = Vec::with_capacity(witt.phi_i.len());
        for (i, phi) in witt.phi_i.iter().enumerate() {
            let val = compute_response(phi, &bli.k_phi_i[i].s);
            phi_hat.push(val);
        }

        Hats {
            z_hat,
            rho_hat,
            gamma_hat,
            psi_hat,
            b_hat,
            phi_hat,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proofs {
    pub S1: PublicKey,
    pub S2a: PublicKey,
    pub S2b: PublicKey,
    pub S3a: PublicKey,
    pub S3b: PublicKey,
    pub S4a: PublicKey,
    pub S4bi: Vec<PublicKey>,
    pub S4c: PublicKey,
}

impl Proofs {
    /// Computes S1 = g^k_z * Product( pk_i ^ (-c * k_b_i) )
    ///
    /// ECC Translation: S1 = (k_z * G) + Sum( pk_i * (-c * k_b_i) )
    pub(crate) fn compute_s1(
        k_z: &Secret,
        k_b_i: &[Secret],
        pk_i: &[PublicKey],
        c: &Scalar,
    ) -> PublicKey {
        let secp = Secp256k1::new();
        assert_eq!(
            k_b_i.len(),
            pk_i.len(),
            "Mismatch between keys and blinding factors"
        );

        // 1. Term 1: A = g^k_z (k_z * G)
        let kz_sk = SecretKey::from_byte_array(k_z.s.to_be_bytes()).unwrap();
        let term_1 = PublicKey::from_secret_key(&secp, &kz_sk);

        let mut accumulator = term_1;

        for (i, pk) in pk_i.iter().enumerate() {
            if k_b_i[i].s == Scalar::ZERO {
                continue;
            }

            let mut exp_sk = SecretKey::from_byte_array(k_b_i[i].s.to_be_bytes())
                .expect("Invalid scalar in k_b");

            // exp_sk = exp_sk * c
            if *c != Scalar::ZERO {
                exp_sk = exp_sk.mul_tweak(c).expect("Scalar multiplication failed");
            } else {
                continue;
            }

            // Negate
            exp_sk = exp_sk.negate();

            let exp_scalar = Scalar::from_be_bytes(exp_sk.secret_bytes()).unwrap();

            let term_i = pk
                .mul_tweak(&secp, &exp_scalar)
                .expect("Point multiplication failed");

            accumulator = accumulator.combine(&term_i).expect("Point addition failed");
        }

        accumulator
    }

    pub(crate) fn compute_sa(k_r: &Secret) -> PublicKey {
        let secp = Secp256k1::new();

        // 1. Convert secret scalar to SecretKey
        let r_sk =
            SecretKey::from_byte_array(k_r.s.to_be_bytes()).expect("Invalid scalar for k_rho");

        // 2. Compute Public Key (g^sk)
        PublicKey::from_secret_key(&secp, &r_sk)
    }

    pub(crate) fn compute_s2b(pk_t: &PublicKey, k_rho: &Secret, k_z: &Secret) -> PublicKey {
        let secp = Secp256k1::new();

        // 1. Term 1: pk_t * k_rho
        // We multiply the threshold pubkey by the rho blinding factor
        let term_1 = pk_t
            .mul_tweak(&secp, &k_rho.s)
            .expect("S2b: Failed to compute pk_t^k_rho");

        // 2. Term 2: g * k_z
        // We get the public key for the z blinding factor
        let kz_sk = SecretKey::from_byte_array(k_z.s.to_be_bytes()).unwrap();
        let term_2 = PublicKey::from_secret_key(&secp, &kz_sk);

        // 3. Combine: term_1 + term_2
        term_1.combine(&term_2).expect("S2b: Point addition failed")
    }

    /// Computes S3b = g^(sum of k_b_i) * h^k_psi
    pub(crate) fn compute_s3b(k_b_i: &[Secret], k_psi: &Secret, h: &PublicKey) -> PublicKey {
        let secp = Secp256k1::new();

        // 1. Term 1: g^(sum of k_b_i)
        // Equivalent to Sum( g^k_b_i )

        // We start with the first element to initialize the accumulator
        // (Assumes k_b_i is not empty)
        let sk_0 = SecretKey::from_byte_array(k_b_i[0].s.to_be_bytes())
            .expect("Invalid scalar in k_b_i[0]");

        let mut term_1_sum = PublicKey::from_secret_key(&secp, &sk_0);

        // Add the rest
        for k_b in k_b_i.iter().skip(1) {
            // Check for zero scalar (identity point)
            if k_b.s == Scalar::ZERO {
                continue;
            }

            let sk =
                SecretKey::from_byte_array(k_b.s.to_be_bytes()).expect("Invalid scalar in k_b_i");
            let p = PublicKey::from_secret_key(&secp, &sk);

            term_1_sum = term_1_sum.combine(&p).expect("Point addition failed");
        }

        // 2. Term 2: h^k_psi
        let term_2 = h
            .mul_tweak(&secp, &k_psi.s)
            .expect("Failed to compute h^k_psi");

        // 3. Combine
        term_1_sum
            .combine(&term_2)
            .expect("Final S3b combination failed")
    }

    /// Computes Vector S4bi:
    /// S4bi[j] = g^(k_b_i[j]) * h_i[j]^(k_gamma)
    pub(crate) fn compute_s4bi(
        k_b_i: &[Secret],
        k_gamma: &Secret,
        h_i: &TracingKeys,
    ) -> Vec<PublicKey> {
        let secp = Secp256k1::new();
        assert_eq!(
            k_b_i.len(),
            h_i.tks.len(),
            "Mismatch between secrets and h_i generators"
        );

        let mut s4bi_vec = Vec::with_capacity(k_b_i.len());

        for (j, k_b) in k_b_i.iter().enumerate() {
            // 1. Term 1: g^(k_b)
            // (Standard Generator G * k_b)
            let kb_sk =
                SecretKey::from_byte_array(k_b.s.to_be_bytes()).expect("Invalid scalar in k_b_i");
            let term_1 = PublicKey::from_secret_key(&secp, &kb_sk);

            // 2. Term 2: h_i[j]^(k_gamma)
            // (Specific generator h_i * k_gamma)
            let h_gen = h_i.tks[j];
            let term_2 = h_gen
                .mul_tweak(&secp, &k_gamma.s)
                .expect("Failed to compute h_i^k_gamma");

            // 3. Combine
            let result = term_1.combine(&term_2).expect("Point addition failed");

            s4bi_vec.push(result);
        }

        s4bi_vec
    }

    /// Computes S4c = Sum( (v_i ^ (alpha^(i+1) * k_b_i)) * (h_i ^ k_phi_i) )
    pub(crate) fn compute_s4c(
        v_i: &[PublicKey],
        alpha: &Scalar,
        k_b_i: &[Secret],
        h_i: &TracingKeys,
        k_phi_i: &[Secret],
    ) -> PublicKey {
        let secp = Secp256k1::new();

        let len = v_i.len();
        if len == 0 {
            panic!("Vectors cannot be empty for S4c");
        }
        assert!(
            k_b_i.len() == len && h_i.tks.len() == len && k_phi_i.len() == len,
            "Dimension mismatch in compute_s4c"
        );

        // Helper: safely multiply two Scalars (res = s1 * s2)
        let mul_scalars = |s1: &Scalar, s2: &Scalar| -> Scalar {
            if *s1 == Scalar::ZERO || *s2 == Scalar::ZERO {
                return Scalar::ZERO;
            }
            // We use SecretKey for the math, then convert back to Scalar
            let mut sk = SecretKey::from_byte_array(s1.to_be_bytes()).unwrap();
            sk = sk.mul_tweak(s2).expect("Scalar multiplication failed");
            Scalar::from_be_bytes(sk.secret_bytes()).unwrap()
        };

        let mut current_alpha_pow = *alpha; // Starts at alpha^1

        let calc_term = |index: usize, alpha_val: &Scalar| -> PublicKey {
            // 1. Part A: v_i ^ (alpha_val * k_b_i)
            // Calculate scalar coefficient first
            let coeff_a = mul_scalars(alpha_val, &k_b_i[index].s);

            let term_a = if coeff_a == Scalar::ZERO {
                // Handle zero scalar case if necessary, though unlikely in valid proofs.
                // For now we assume we can't multiply by zero easily on PublicKey
                // without resulting in Identity (which isn't a PublicKey type).
                // We panic to keep it safe, or you can implement Identity handling.
                panic!("computed zero scalar coeff_a");
            } else {
                // FIX: Pass the Scalar 'coeff_a' directly
                v_i[index].mul_tweak(&secp, &coeff_a).unwrap()
            };

            // 2. Part B: h_i ^ k_phi_i
            // FIX: Access the Scalar '.s' from the Secret directly
            let scalar_b = &k_phi_i[index].s;
            let term_b = h_i.tks[index].mul_tweak(&secp, scalar_b).unwrap();

            // 3. Combine
            term_a.combine(&term_b).expect("Point addition failed")
        };

        // --- Execute Loop ---
        let mut accumulator = calc_term(0, &current_alpha_pow);

        for i in 1..len {
            current_alpha_pow = mul_scalars(&current_alpha_pow, alpha);
            let next_term = calc_term(i, &current_alpha_pow);
            accumulator = accumulator
                .combine(&next_term)
                .expect("Accumulator addition failed");
        }

        accumulator
    }

    /// Main function to generate all proof components
    pub fn compute_proofs(
        bli: &Blinds,
        pk: &PK,
        h_i_vec: &TracingKeys,
        v_i: &[PublicKey],
        c: &Scalar,
        alpha: &Scalar,
    ) -> Self {
        // 1. Prepare Public Key Vectors
        // Extract pk from KeyPairs
        let pk_i_vec: Vec<PublicKey> = pk.pk_i.clone();

        // 2. Compute S1
        // S1 = g^k_z * Product( pk_i ^ (-c * k_b_i) )
        // Using previously named 'verify_s1' logic
        let S1 = Proofs::compute_s1(&bli.k_z, &bli.k_b_i, &pk_i_vec, c);

        // 3. Compute S2a (Generic commitment to G)
        // S2a = g^k_rho
        let S2a = Proofs::compute_sa(&bli.k_rho);

        // 4. Compute S2b
        // S2b = pk_t^k_rho * g^k_z
        let S2b = Proofs::compute_s2b(&pk.pk_t, &bli.k_rho, &bli.k_z);

        // 5. Compute S3a
        // S3a = g^k_psi (Same logic as S2a, different secret)
        let S3a = Proofs::compute_sa(&bli.k_psi);

        // 6. Compute S3b
        // h = Second generator
        // S3b = g^(sum k_b_i) * h^k_psi
        let h = get_second_generator_h();
        let S3b = Proofs::compute_s3b(&bli.k_b_i, &bli.k_psi, &h);

        // 7. Compute S4a
        // S4a = g^k_gamma (Same logic as S2a, different secret)
        let S4a = Proofs::compute_sa(&bli.k_gamma);

        // 8. Compute S4bi (Vector)
        // S4bi = g^k_b_i * h_i^k_gamma
        let S4bi = Proofs::compute_s4bi(&bli.k_b_i, &bli.k_gamma, &h_i_vec);

        // 9. Compute S4c
        // S4c = Product( v_i ^ (alpha^(i+1)*k_b_i) * h_i^k_phi_i )
        let S4c = Proofs::compute_s4c(v_i, alpha, &bli.k_b_i, &h_i_vec, &bli.k_phi_i);

        Proofs {
            S1,
            S2a,
            S2b,
            S3a,
            S3b,
            S4a,
            S4bi,
            S4c,
        }
    }

    /// Verifies: S1 * R^beta * (Product pk_i ^ (b_hat_i * c)) == g^z_hat
    /// Returns Ok(true) if valid.
    pub(crate) fn verify_s1(
        S1: &PublicKey,
        R: &PublicKey,
        pks: &[PublicKey], // Vector of public keys
        b_hat: &[Scalar],
        c: &Scalar,
        beta: &Scalar,
        z_hat: &Scalar,
    ) -> Result<bool, String> {
        let secp = Secp256k1::new();

        if pks.len() != b_hat.len() {
            return Err("Vector length mismatch between keys and responses".to_string());
        }

        // --- LHS Calculation ---

        // 1. Term 2: R^beta
        // R * beta
        let term_r = R
            .mul_tweak(&secp, beta)
            .map_err(|_| "Failed to compute R^beta")?;

        // 2. Term 3: Sum( pk_i ^ (b_hat_i * c) )
        // We accumulate this sum starting from Identity (or handle first element).
        // Since we don't have explicit Identity in PublicKey, we calculate the first term.

        // A term with a zero exponent is the identity point, which secp256k1's
        // PublicKey cannot represent - such terms are simply skipped instead of
        // aborting the whole verification.
        let calc_term_i = |i: usize| -> Result<Option<PublicKey>, String> {
            if *c == Scalar::ZERO || b_hat[i] == Scalar::ZERO {
                return Ok(None);
            }

            let mut sk = SecretKey::from_byte_array(b_hat[i].to_be_bytes())
                .map_err(|_| "Invalid scalar in b_hat")?;
            sk = sk.mul_tweak(c).map_err(|_| "Scalar mul failed")?;

            let scalar_exp = Scalar::from_be_bytes(sk.secret_bytes()).unwrap();

            pks[i]
                .mul_tweak(&secp, &scalar_exp)
                .map(Some)
                .map_err(|_| "Failed to compute pk^exponent".to_string())
        };

        let mut term_sum_pk: Option<PublicKey> = None;

        for i in 0..pks.len() {
            if let Some(next_term) = calc_term_i(i)? {
                term_sum_pk = match term_sum_pk {
                    Some(acc) => Some(
                        acc.combine(&next_term)
                            .map_err(|_| "Point addition failed in sum loop")?,
                    ),
                    None => Some(next_term),
                };
            }
        }

        // 3. Combine LHS: S1 + R^beta + Sum(...)
        let mut lhs = S1
            .combine(&term_r)
            .map_err(|_| "Final LHS combination failed")?;

        if let Some(sum) = term_sum_pk {
            lhs = lhs
                .combine(&sum)
                .map_err(|_| "Final LHS combination failed")?;
        }

        // --- RHS Calculation ---
        // g^z_hat
        let z_sk = SecretKey::from_byte_array(z_hat.to_be_bytes())
            .map_err(|_| "Invalid scalar for z_hat")?;
        let rhs = PublicKey::from_secret_key(&secp, &z_sk);

        // --- Comparison ---
        Ok(lhs == rhs)
    }

    /// Verifies: Sa * c0^beta == g^r_hat
    ///
    /// ECC Translation: Sa + (c0 * beta) == r_hat * G
    pub(crate) fn verify_sa(
        sa: &PublicKey,
        c0: &PublicKey,
        beta: &Scalar,
        r_hat: &Scalar,
    ) -> Result<bool, String> {
        let secp = Secp256k1::new();

        // --- LHS Calculation ---
        // Term: c0 * beta
        let term_c0 = c0
            .mul_tweak(&secp, beta)
            .map_err(|_| "Failed to compute c0^beta".to_string())?;

        // LHS: Sa + term_c0
        let lhs = sa
            .combine(&term_c0)
            .map_err(|_| "LHS point addition failed".to_string())?;

        // --- RHS Calculation ---
        // RHS: g^r_hat
        let r_hat_sk = SecretKey::from_byte_array(r_hat.to_be_bytes())
            .map_err(|_| "Invalid scalar for r_hat".to_string())?;

        let rhs = PublicKey::from_secret_key(&secp, &r_hat_sk);

        // --- Comparison ---
        Ok(lhs == rhs)
    }

    /// Verifies: S2b * c1^beta == pk_t^rho_hat * g^z_hat
    ///
    /// ECC Translation: S2b + (c1 * beta) == (pk_t * rho_hat) + (g * z_hat)
    pub(crate) fn verify_s2b(
        s2b: &PublicKey,
        c1: &PublicKey,
        beta: &Scalar,
        pk_t: &PublicKey,
        rho_hat: &Scalar,
        z_hat: &Scalar,
    ) -> Result<bool, String> {
        let secp = Secp256k1::new();

        // --- LHS Calculation ---
        // Term: c1 * beta
        let term_c1 = c1
            .mul_tweak(&secp, beta)
            .map_err(|_| "Failed to compute c1^beta".to_string())?;

        // LHS: S2b + (c1 * beta)
        let lhs = s2b
            .combine(&term_c1)
            .map_err(|_| "LHS combination failed".to_string())?;

        // --- RHS Calculation ---

        // Term 1: pk_t^rho_hat (pk_t * rho_hat)
        let term_pkt = pk_t
            .mul_tweak(&secp, rho_hat)
            .map_err(|_| "Failed to compute pk_t^rho_hat".to_string())?;

        // Term 2: g^z_hat (z_hat * G)
        let z_sk = SecretKey::from_byte_array(z_hat.to_be_bytes())
            .map_err(|_| "Invalid scalar z_hat".to_string())?;
        let term_g = PublicKey::from_secret_key(&secp, &z_sk);

        // RHS: term_pkt + term_g
        let rhs = term_pkt
            .combine(&term_g)
            .map_err(|_| "RHS combination failed".to_string())?;

        // --- Comparison ---
        Ok(lhs == rhs)
    }

    /// Verifies: S3b * T1^beta == g^(sum b_hat_i) * h^psi_hat
    ///
    /// ECC Translation: S3b + (T1 * beta) == (G * sum(b_hat_i)) + (h * psi_hat)
    pub(crate) fn verify_s3b(
        s3b: &PublicKey,
        t1: &PublicKey,
        h: &PublicKey,
        beta: &Scalar,
        b_hats: &[Scalar],
        psi_hat: &Scalar,
    ) -> Result<bool, String> {
        let secp = Secp256k1::new();

        // --- LHS Calculation ---
        // Term: T1 * beta
        let term_t1 = t1
            .mul_tweak(&secp, beta)
            .map_err(|_| "Failed to compute T1^beta".to_string())?;

        // LHS: S3b + (T1 * beta)
        let lhs = s3b
            .combine(&term_t1)
            .map_err(|_| "LHS combination failed".to_string())?;

        // --- RHS Calculation ---

        // Term 1: g^(sum of b_hat_i)
        // Optimization: Sum scalars first, then multiply point once.
        // sum_b = b_hat[0] + b_hat[1] + ...

        let mut sum_b_sk = if b_hats.is_empty() {
            // If vector empty, sum is 0.
            // We can't make SecretKey from 0 easily to represent identity exponent
            // without hacks. Returning error for empty proof vector is safer.
            return Err("Empty b_hat vector".to_string());
        } else {
            SecretKey::from_byte_array(b_hats[0].to_be_bytes()).unwrap()
        };

        for b in b_hats.iter().skip(1) {
            sum_b_sk = sum_b_sk
                .add_tweak(b)
                .map_err(|_| "Scalar addition failed (sum b_hat)".to_string())?;
        }

        // Check if sum ended up 0 (unlikely but possible in math)
        // If 0, the term is Identity. PublicKey doesn't support Identity.
        // For standard Schnorr proofs, if sum is 0, we can skip combining.
        // We calculate the point G * sum.
        let term_g = PublicKey::from_secret_key(&secp, &sum_b_sk);

        // Term 2: h^psi_hat
        let term_h = h
            .mul_tweak(&secp, psi_hat)
            .map_err(|_| "Failed to compute h^psi_hat".to_string())?;

        // RHS: (G * sum) + (h * psi_hat)
        let rhs = term_g
            .combine(&term_h)
            .map_err(|_| "RHS combination failed".to_string())?;

        // --- Comparison ---
        Ok(lhs == rhs)
    }

    /// Verifies vector: S4b[i] * v[i]^beta == g^(b_hat[i]) * h[i]^gamma_hat
    ///
    /// ECC Translation: S4b[i] + (v[i] * beta) == (g * b_hat[i]) + (h[i] * gamma_hat)
    pub(crate) fn verify_s4bi(
        s4b: &[PublicKey],
        v: &[PublicKey],
        h: &[PublicKey],
        beta: &Scalar,
        b_hat: &[Scalar],
        gamma_hat: &Scalar,
    ) -> Result<bool, String> {
        let secp = Secp256k1::new();
        let len = s4b.len();

        if v.len() != len || h.len() != len || b_hat.len() != len {
            return Err("Vector dimension mismatch in verify_s4bi".to_string());
        }

        for i in 0..len {
            // --- LHS Calculation ---
            // Term: v[i] * beta
            let term_v = v[i]
                .mul_tweak(&secp, beta)
                .map_err(|_| format!("Failed to compute v[{}]^beta", i))?;

            // LHS: S4b[i] + term_v
            let lhs = s4b[i]
                .combine(&term_v)
                .map_err(|_| format!("LHS combination failed at index {}", i))?;

            // --- RHS Calculation ---

            // Term 1: g^(b_hat[i])
            let b_sk = SecretKey::from_byte_array(b_hat[i].to_be_bytes()).unwrap();
            let term_g = PublicKey::from_secret_key(&secp, &b_sk);

            // Term 2: h[i]^gamma_hat
            let term_h = h[i]
                .mul_tweak(&secp, gamma_hat)
                .map_err(|_| format!("Failed to compute h[{}]^gamma_hat", i))?;

            // RHS: term_g + term_h
            let rhs = term_g
                .combine(&term_h)
                .map_err(|_| format!("RHS combination failed at index {}", i))?;

            // --- Check ---
            if lhs != rhs {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Verifies S4c equation.
    /// Returns true if valid.
    pub(crate) fn verify_s4c(
        s4c: &PublicKey,
        v: &[PublicKey],
        h: &[PublicKey],
        beta: &Scalar,
        alpha: &Scalar,
        b_hat: &[Scalar],
        phi_hat: &[Scalar],
    ) -> Result<bool, String> {
        let secp = Secp256k1::new();
        let len = v.len();

        if h.len() != len || b_hat.len() != len || phi_hat.len() != len {
            return Err("Vector dimension mismatch in verify_s4c".to_string());
        }

        // --- Helper: Scalar Multiplication ---
        let mul_scalars = |s1: &Scalar, s2: &Scalar| -> Scalar {
            let mut sk = SecretKey::from_byte_array(s1.to_be_bytes()).unwrap();
            sk = sk.mul_tweak(s2).unwrap(); // ignore error for simplicity in helper
            Scalar::from_be_bytes(sk.secret_bytes()).unwrap()
        };

        // --- LHS Calculation ---
        // LHS = S4c + Sum( v[i] ^ (beta * alpha^(i+1)) )

        let mut lhs_accum = *s4c;
        let mut current_alpha = *alpha; // alpha^1

        for i in 0..len {
            // Exponent: beta * alpha^(i+1)
            let exp = mul_scalars(beta, &current_alpha);

            let term = v[i]
                .mul_tweak(&secp, &exp)
                .map_err(|_| format!("Failed LHS mul at {}", i))?;

            lhs_accum = lhs_accum
                .combine(&term)
                .map_err(|_| "Failed LHS combine".to_string())?;

            // Update alpha for next iteration
            if i < len - 1 {
                current_alpha = mul_scalars(&current_alpha, alpha);
            }
        }

        // --- RHS Calculation ---
        // RHS = Sum( v[i]^(alpha^(i+1) * b_hat[i]) * h[i]^phi_hat[i] )

        // Reset alpha
        current_alpha = *alpha;

        // Initialize RHS accumulator with first term to avoid Identity issues
        // (We assume len > 0 based on logic, but good to handle)
        if len == 0 {
            return Ok(false);
        }

        let calc_rhs_term = |i: usize, alpha_val: &Scalar| -> Result<PublicKey, String> {
            // Term A: v[i] ^ (alpha * b_hat)
            let exp_a = mul_scalars(alpha_val, &b_hat[i]);
            let term_a = v[i]
                .mul_tweak(&secp, &exp_a)
                .map_err(|_| format!("Failed RHS term A at {}", i))?;

            // Term B: h[i] ^ phi_hat
            let term_b = h[i]
                .mul_tweak(&secp, &phi_hat[i])
                .map_err(|_| format!("Failed RHS term B at {}", i))?;

            term_a
                .combine(&term_b)
                .map_err(|_| "Failed RHS combine term".to_string())
        };

        let mut rhs_accum = calc_rhs_term(0, &current_alpha)?;

        for i in 1..len {
            current_alpha = mul_scalars(&current_alpha, alpha);
            let next_term = calc_rhs_term(i, &current_alpha)?;
            rhs_accum = rhs_accum
                .combine(&next_term)
                .map_err(|_| "Failed RHS accumulation".to_string())?;
        }

        // --- Compare ---
        Ok(lhs_accum == rhs_accum)
    }

    /// Public Verify Function
    /// Orchestrates all sub-verifications.
    /// Returns Ok(true) if all pass, or Err(String) if any check fails or errors.
    ///
    /// The challenges c, alpha and beta are re-derived from `stmt` here; they are
    /// never taken from the prover. `stmt.ct` / `stmt.R` must be the ones carried
    /// in `sigma`, otherwise the transcript will not match and verification fails.
    ///
    /// Only public data is needed: the tracing keys are the public h_i, and the
    /// tracer's public key comes from `stmt.pk.pk_t`. Anyone can run this.
    pub fn verify(proof: &Proofs, sigma: &Sigma, stmt: &Statement) -> Result<bool, String> {
        let ts = stmt.T;
        let v0 = stmt.v0;
        let v = stmt.v;
        let pk = stmt.pk;

        // 0. Re-derive the Fiat-Shamir transcript and pin the prover to it.
        let c = stmt.c();
        let alpha = stmt.alpha(&c);
        let beta = stmt.beta(&alpha, proof);

        if beta != sigma.pi.beta {
            return Err(
                "Fiat-Shamir check failed: beta does not match the statement and commitments"
                    .to_string(),
            );
        }
        if *stmt.R != sigma.R {
            return Err("Statement R does not match the R carried in sigma".to_string());
        }
        if *stmt.ct != sigma.ct {
            return Err("Statement ct does not match the ct carried in sigma".to_string());
        }

        // 1. Prepare Data
        let h_generator = get_second_generator_h();

        // 2. Execute Verifications Sequence

        // Check 1: S1 (Schnorr / Linear Relation for z and b)
        let kp_s = pk.pk_i.clone(); // Extract public keys for S1 verification
        let s1_ok = Proofs::verify_s1(
            &proof.S1,
            &sigma.R,
            &kp_s,
            &sigma.pi.hats.b_hat,
            &c,
            &beta,
            &sigma.pi.hats.z_hat,
        )?;
        if !s1_ok {
            return Err("S1 verification failed".to_string());
        }

        // Check 2: S2a (Commitment to rho randomness)
        // Verifies: S2a * cs.c0^beta == g^rho_hat
        let s2a_ok = Proofs::verify_sa(&proof.S2a, &sigma.ct.c0, &beta, &sigma.pi.hats.rho_hat)?;
        if !s2a_ok {
            return Err("S2a verification failed".to_string());
        }

        // Check 3: S2b (Consistency of Ciphertext c1)
        // Verifies: S2b * cs.c1^beta == pk_t^rho_hat * g^z_hat
        let s2b_ok = Proofs::verify_s2b(
            &proof.S2b,
            &sigma.ct.c1,
            &beta,
            &pk.pk_t,
            &sigma.pi.hats.rho_hat,
            &sigma.pi.hats.z_hat,
        )?;
        if !s2b_ok {
            return Err("S2b verification failed".to_string());
        }

        // Check 4: S3a (Commitment to psi randomness)
        // Verifies: S3a * ts.c0^beta == g^psi_hat
        let s3a_ok = Proofs::verify_sa(&proof.S3a, &ts.c0, &beta, &sigma.pi.hats.psi_hat)?;
        if !s3a_ok {
            return Err("S3a verification failed".to_string());
        }

        // Check 5: S3b (Tally/Sum Commitment Consistency)
        // Verifies: S3b * ts.c1^beta == g^(sum b_hat) * h^psi_hat
        let s3b_ok = Proofs::verify_s3b(
            &proof.S3b,
            &ts.c1,
            &h_generator,
            &beta,
            &sigma.pi.hats.b_hat,
            &sigma.pi.hats.psi_hat,
        )?;
        if !s3b_ok {
            return Err("S3b verification failed".to_string());
        }

        // Check 6: S4a (Commitment to gamma randomness)
        // Verifies: S4a * v0^beta == g^gamma_hat
        let s4a_ok = Proofs::verify_sa(&proof.S4a, v0, &beta, &sigma.pi.hats.gamma_hat)?;
        if !s4a_ok {
            return Err("S4a verification failed".to_string());
        }

        // Check 7: S4bi (Individual Value Commitments)
        // Verifies: S4bi[i] * v[i]^beta == g^b_hat[i] * h_i^gamma_hat
        let h_pks: &[PublicKey] = &stmt.tks.tks;
        let s4bi_ok = Proofs::verify_s4bi(
            &proof.S4bi,
            v,
            h_pks,
            &beta,
            &sigma.pi.hats.b_hat,
            &sigma.pi.hats.gamma_hat,
        )?;
        if !s4bi_ok {
            return Err("S4bi verification failed".to_string());
        }

        // Check 8: S4c (Bit Consistency / Range Proof)
        // Verifies aggregated power checks
        let s4c_ok = Proofs::verify_s4c(
            &proof.S4c,
            v,
            h_pks,
            &beta,
            &alpha,
            &sigma.pi.hats.b_hat,
            &sigma.pi.hats.phi_hat,
        )?;
        if !s4c_ok {
            return Err("S4c verification failed".to_string());
        }

        // If all passed
        Ok(true)
    }
}

/// Computes the target Public Key for Schnorr verification.
/// Result = R * (Product of pk_i in quorum)^c
pub fn schnorr_signature(R: &PublicKey, quo: &Quorum, c: &Scalar) -> PublicKey {
    let secp = Secp256k1::new();

    // Start accumulator with R
    let mut accumulator = *R;

    for (pk, bit) in &quo.participants {
        // Only include participants who are present (bit = 1)
        if *bit == 1 {
            // Compute term = pk_i * c
            let term = pk
                .mul_tweak(&secp, c)
                .expect("Failed to compute pk^c in schnorr_signature");

            // Add to accumulator
            accumulator = accumulator
                .combine(&term)
                .expect("Point addition failed in schnorr_signature");
        }
    }

    accumulator
}

// --- Add to src/taps.rs ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pi {
    #[serde(with = "serde_scalar")]
    pub beta: Scalar,
    pub hats: Hats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sigma {
    pub R: PublicKey,
    pub ct: ElGamalCiphertext,
    pub pi: Pi,
    #[serde(with = "serde_scalar")]
    pub tg: Scalar, // The signature response 's'
    pub comm: PublicKey, // The signature public nonce 'R_schnorr' (g^r)
}

impl Sigma {
    /// signs the protocol execution state.
    ///
    /// Generates a Schnorr signature (sigma) binding the message 'm',
    /// the aggregate nonce 'R', the ciphertext 'ct', and the proof 'pi'.
    ///
    /// Formula: tg = r + h * sk
    /// Where h = H(m, R, ct, pi...)
    pub fn sign(
        kp_cs: &KeyPair, // The Signer's KeyPair (sk used for signing)
        m: &[u8],        // Message bytes
        R: &PublicKey,   // Aggregate Nonce R
        ct: &ElGamalCiphertext,
        pi: Pi,
    ) -> Self {
        // 1. Create a fresh random Commitment (Nonce r)
        let comm_struct = Commit::commit();
        let r_sk = comm_struct.nonce.sk;
        let comm_pk = comm_struct.nonce.pk;

        // 2. Compute Hash h
        // h = H(m, R, ct.c0, ct.c1, pi.beta, pi.hats...)
        let mut hasher = Sha256::new();

        // Bind the verification key into the challenge (key-prefixed Schnorr).
        hasher.update(&kp_cs.pk.serialize());
        hasher.update(&(m.len() as u64).to_be_bytes());
        hasher.update(m);
        hasher.update(&R.serialize());
        hasher.update(&ct.c0.serialize());
        hasher.update(&ct.c1.serialize());
        hasher.update(&pi.beta.to_be_bytes());

        // Hash the Hats (Responses)
        hasher.update(&pi.hats.z_hat.to_be_bytes());
        hasher.update(&pi.hats.rho_hat.to_be_bytes());
        hasher.update(&pi.hats.gamma_hat.to_be_bytes());
        hasher.update(&pi.hats.psi_hat.to_be_bytes());

        for b_hat in &pi.hats.b_hat {
            hasher.update(&b_hat.to_be_bytes());
        }
        for phi_hat in &pi.hats.phi_hat {
            hasher.update(&phi_hat.to_be_bytes());
        }

        // Add the commitment public key (Standard Fiat-Shamir)
        hasher.update(&comm_pk.serialize());

        let h = hash_to_scalar(b"TAPS/sigma-schnorr/v1", &hasher.finalize());

        // 3. Compute tg = r + h * sk
        // (Standard Schnorr Signature Equation)

        // Term: h * sk
        let mut term_sk = kp_cs.sk;
        term_sk = term_sk.mul_tweak(&h).expect("Signing: h * sk failed");

        // Total: r + (h * sk)
        // We use the nonce secret key 'r_sk' as the base
        let tg_sk = r_sk
            .add_tweak(&Scalar::from_be_bytes(term_sk.secret_bytes()).unwrap())
            .expect("Signing: r + h*sk failed");

        let tg = Scalar::from_be_bytes(tg_sk.secret_bytes()).unwrap();

        // 4. Output Sigma
        // Note: We send 'comm_pk' (Public Key of nonce), not the private nonce.
        Sigma {
            R: *R,
            ct: ct.clone(),
            pi,
            tg,
            comm: comm_pk,
        }
    }

    /// Verifies the Schnorr signature in Sigma.
    /// Checks: g^tg == comm + (pk_cs * h)
    pub fn verify(
        pk: &PK, // We only use .pk from this
        m: &[u8],
        sig: &Sigma,
    ) -> Result<bool, String> {
        let secp = Secp256k1::new();

        // 1. Recompute Hash h
        // Must match the exact order and fields used in 'sign'
        let mut hasher = Sha256::new();

        hasher.update(&pk.pk_cs.serialize());
        hasher.update(&(m.len() as u64).to_be_bytes());
        hasher.update(m);
        hasher.update(&sig.R.serialize());
        hasher.update(&sig.ct.c0.serialize());
        hasher.update(&sig.ct.c1.serialize());
        hasher.update(&sig.pi.beta.to_be_bytes());

        // Hash Hats
        hasher.update(&sig.pi.hats.z_hat.to_be_bytes());
        hasher.update(&sig.pi.hats.rho_hat.to_be_bytes());
        hasher.update(&sig.pi.hats.gamma_hat.to_be_bytes());
        hasher.update(&sig.pi.hats.psi_hat.to_be_bytes());

        for b_hat in &sig.pi.hats.b_hat {
            hasher.update(&b_hat.to_be_bytes());
        }
        for phi_hat in &sig.pi.hats.phi_hat {
            hasher.update(&phi_hat.to_be_bytes());
        }

        // Include the Commitment R (Standard Fiat-Shamir)
        // In 'sign', we hashed sig.comm (the nonce pk)
        hasher.update(&sig.comm.serialize());

        let h = hash_to_scalar(b"TAPS/sigma-schnorr/v1", &hasher.finalize());

        // 2. Compute LHS = g^tg
        // We take the scalar 'tg' and multiply by generator G.
        let tg_sk = SecretKey::from_byte_array(sig.tg.to_be_bytes()).unwrap();
        let lhs = PublicKey::from_secret_key(&secp, &tg_sk);

        // 3. Compute RHS = comm + (pk_cs * h)

        // Term: pk_cs * h
        let term_pk = pk
            .pk_cs
            .mul_tweak(&secp, &h)
            .map_err(|_| "Verification failed: pk * h invalid")?;

        // Total: comm + term_pk
        let rhs = sig
            .comm
            .combine(&term_pk)
            .map_err(|_| "Verification failed: Point addition")?;

        // 4. Compare
        if lhs == rhs {
            Ok(true)
        } else {
            // Detailed error for debugging
            Err("Signature verification failed: LHS != RHS".to_string())
        }
    }
}
