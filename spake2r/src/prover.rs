pub use crate::{
    ed25519::Ed25519Group,
    error::{Error, Result},
    group::Group,
    Password,
};
use crate::{Identity, MaybeUtf8};

use alloc::vec::Vec;
use core::fmt;
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "getrandom")]
use rand_core::OsRng;

/// SPake2r algorithm.
#[derive(Eq, PartialEq, Clone)]
pub struct Prover<G: Group> {
    pub(crate) id_prover: Identity,
    pub(crate) id_verifier: Identity,
    msg1: Vec<u8>,
    pub(crate) x: G::Scalar,
    pub(crate) password_vec: Vec<u8>,
    pub(crate) password_scalar: G::Scalar,
}

impl<G: Group> Prover<G> {
    /// Start with identity `idProver`.
    ///
    /// Uses the system RNG.
    #[cfg(feature = "getrandom")]
    #[must_use]
    pub fn start(
        password: &Password,
        id_prover: &Identity,
        id_verifier: &Identity,
    ) -> (Self, Vec<u8>) {
        Self::start_with_rng(password, id_prover, id_verifier, OsRng)
    }

    /// Start with identity `idProver` and the provided cryptographically secure RNG.
    #[must_use]
    pub fn start_with_rng(
        password: &Password,
        id_prover: &Identity,
        id_verifier: &Identity,
        mut csrng: impl CryptoRng + RngCore,
    ) -> (Self, Vec<u8>) {
        let x: G::Scalar = G::random_scalar(&mut csrng);
        Self::start_deterministic(password, id_prover, id_verifier, x)
    }

    pub(crate) fn start_deterministic(
        password: &Password,
        id_prover: &Identity,
        id_verifier: &Identity,
        x: G::Scalar,
    ) -> (Self, Vec<u8>) {
        let password_scalar: G::Scalar = G::hash_to_scalar(password);

        // prover: X = B*x + M*pw
        let blinding = G::const_m();

        let m1: G::Element = G::add(
            &G::basepoint_mult(&x),
            &G::scalarmult(&blinding, &password_scalar),
        );
        //let m1: G::Element = &G::basepoint_mult(&x) + &(blinding * &password_scalar);
        let msg1: Vec<u8> = G::element_to_bytes(&m1);
        let mut password_vec = Vec::new();
        password_vec.extend_from_slice(password);

        let mut msg_and_side = vec![0x41]; //prover
        msg_and_side.extend_from_slice(&msg1);

        (
            Self {
                id_prover: id_prover.clone(),
                id_verifier: id_verifier.clone(),
                x,
                msg1,
                password_vec,    // string
                password_scalar, // scalar
            },
            msg_and_side,
        )
    }

    /// Finish SPake2r.
    pub fn finish(self, msg2: &[u8]) -> Result<Vec<u8>> {
        if msg2.len() != 1 + G::element_length() {
            return Err(Error::WrongLength);
        }
        let msg_side = msg2[0];

        match msg_side {
            0x42 => (), // 'Verifier'
            _ => return Err(Error::BadSide),
        };

        let msg2_element = match G::bytes_to_element(&msg2[1..]) {
            Some(x) => x,
            None => return Err(Error::CorruptMessage),
        };

        // prover: K = (Y+N*(-pw))*x

        let unblinding = G::const_n();
        let tmp1 = G::scalarmult(&unblinding, &G::scalar_neg(&self.password_scalar));
        let tmp2 = G::add(&msg2_element, &tmp1);
        let key_element = G::scalarmult(&tmp2, &self.x);
        let key_bytes = G::element_to_bytes(&key_element);

        // key = H(H(pw) + H(idProver) + H(idVerifier) + X + Y + K)
        //transcript = b"".join([sha256(pw).digest(),
        //                       sha256(idProver).digest(), sha256(idVerifier).digest(),
        //                       X_msg, Y_msg, K_bytes])
        //key = sha256(transcript).digest()
        // note that both sides must use the same order

        Ok(G::hash_identities(
            &self.password_vec,
            &self.id_prover,
            &self.id_verifier,
            self.msg1.as_slice(),
            &msg2[1..],
            &key_bytes,
        ))
    }
}

impl<G: Group> fmt::Debug for Prover<G> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("Prover")
            .field("group", &G::name())
            .field("idProver", &MaybeUtf8(&self.id_prover.0))
            .field("idVerifier", &MaybeUtf8(&self.id_verifier.0))
            .finish()
    }
}
