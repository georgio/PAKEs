//! "Edwards25519" elliptic curve group.

use crate::{c2_Element, c2_Scalar, Group};
use alloc::vec::Vec;
use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, edwards::CompressedEdwardsY};
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

/// Ed25519 elliptic curve group.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Ed25519Group;

impl Group for Ed25519Group {
    type Scalar = c2_Scalar;
    type Element = c2_Element;
    type TranscriptHash = Sha256;

    fn name() -> &'static str {
        "Ed25519"
    }

    fn const_m() -> c2_Element {
        // python -c "import binascii, spake2; b=binascii.hexlify(spake2.ParamsEd25519.M.to_bytes()); print(', '.join(['0x'+b[i:i+2] for i in range(0,len(b),2)]))"
        // 15cfd18e385952982b6a8f8c7854963b58e34388c8e6dae891db756481a02312
        CompressedEdwardsY([
            0x15, 0xcf, 0xd1, 0x8e, 0x38, 0x59, 0x52, 0x98, 0x2b, 0x6a, 0x8f, 0x8c, 0x78, 0x54,
            0x96, 0x3b, 0x58, 0xe3, 0x43, 0x88, 0xc8, 0xe6, 0xda, 0xe8, 0x91, 0xdb, 0x75, 0x64,
            0x81, 0xa0, 0x23, 0x12,
        ])
        .decompress()
        .unwrap()
    }

    fn const_n() -> c2_Element {
        // python -c "import binascii, spake2; b=binascii.hexlify(spake2.ParamsEd25519.N.to_bytes()); print(', '.join(['0x'+b[i:i+2] for i in range(0,len(b),2)]))"
        // f04f2e7eb734b2a8f8b472eaf9c3c632576ac64aea650b496a8a20ff00e583c3
        CompressedEdwardsY([
            0xf0, 0x4f, 0x2e, 0x7e, 0xb7, 0x34, 0xb2, 0xa8, 0xf8, 0xb4, 0x72, 0xea, 0xf9, 0xc3,
            0xc6, 0x32, 0x57, 0x6a, 0xc6, 0x4a, 0xea, 0x65, 0x0b, 0x49, 0x6a, 0x8a, 0x20, 0xff,
            0x00, 0xe5, 0x83, 0xc3,
        ])
        .decompress()
        .unwrap()
    }

    fn hash_to_scalar(s: &[u8]) -> c2_Scalar {
        ed25519_hash_to_scalar(s)
    }

    fn random_scalar<T>(cspring: &mut T) -> c2_Scalar
    where
        T: RngCore + CryptoRng,
    {
        c2_Scalar::random(cspring)
    }

    fn scalar_neg(s: &c2_Scalar) -> c2_Scalar {
        -s
    }

    fn element_to_bytes(s: &c2_Element) -> Vec<u8> {
        s.compress().as_bytes().to_vec()
    }

    fn element_length() -> usize {
        32
    }

    fn bytes_to_element(b: &[u8]) -> Option<c2_Element> {
        if b.len() != 32 {
            return None;
        }

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(b);

        let cey = CompressedEdwardsY(bytes);
        cey.decompress()
    }

    fn basepoint_mult(s: &c2_Scalar) -> c2_Element {
        ED25519_BASEPOINT_POINT * s
    }
    fn scalarmult(e: &c2_Element, s: &c2_Scalar) -> c2_Element {
        e * s
    }

    fn add(a: &c2_Element, b: &c2_Element) -> c2_Element {
        a + b
    }

    /// Hash `idProver` and `idVerifier` identities.
    fn hash_identities(
        password_vec: &[u8],
        id_prover: &[u8],
        id_verifier: &[u8],
        first_msg: &[u8],
        second_msg: &[u8],
        key_bytes: &[u8],
    ) -> Vec<u8> {
        assert_eq!(first_msg.len(), 32);
        assert_eq!(second_msg.len(), 32);
        // the transcript is fixed-length, made up of 6 32-byte values:
        // byte 0-31   : sha256(pw)
        // byte 32-63  : sha256(idProver)
        // byte 64-95  : sha256(idVerifier)
        // byte 96-127 : X_msg
        // byte 128-159: Y_msg
        // byte 160-191: K_bytes
        let mut transcript = [0u8; 6 * 32];

        let mut pw_hash = Sha256::new();
        pw_hash.update(password_vec);
        transcript[0..32].copy_from_slice(&pw_hash.finalize());

        let mut ida_hash = Sha256::new();
        ida_hash.update(id_prover);
        transcript[32..64].copy_from_slice(&ida_hash.finalize());

        let mut idb_hash = Sha256::new();
        idb_hash.update(id_verifier);
        transcript[64..96].copy_from_slice(&idb_hash.finalize());

        transcript[96..128].copy_from_slice(first_msg);
        transcript[128..160].copy_from_slice(second_msg);
        transcript[160..192].copy_from_slice(key_bytes);

        //println!("transcript: {:?}", transcript.iter().to_hex());

        //let mut hash = G::TranscriptHash::default();
        let mut hash = Sha256::new();
        hash.update(transcript);
        hash.finalize().to_vec()
    }
}

fn ed25519_hash_to_scalar(s: &[u8]) -> c2_Scalar {
    //c2_Scalar::hash_from_bytes::<Sha512>(&s)
    // spake2.py does:
    //  h = HKDF(salt=b"", ikm=s, hash=SHA256, info=b"SPAKE2 pw", len=32+16)
    //  i = int(h, 16)
    //  i % q

    let mut okm = [0u8; 32 + 16];
    Hkdf::<Sha256>::new(Some(b""), s)
        .expand(b"SPAKE2 pw", &mut okm)
        .unwrap();
    //println!("expanded:   {}{}", "................................", okm.iter().to_hex()); // ok

    let mut reducible = [0u8; 64]; // little-endian
    for (i, x) in okm.iter().enumerate().take(32 + 16) {
        reducible[32 + 16 - 1 - i] = *x;
    }
    //println!("reducible:  {}", reducible.iter().to_hex());
    c2_Scalar::from_bytes_mod_order_wide(&reducible)
    //let reduced = c2_Scalar::reduce(&reducible);
    //println!("reduced:    {}", reduced.as_bytes().to_hex());
    //println!("done");
    //reduced
}
