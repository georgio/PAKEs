#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]

//! # Usage
//!
//! Alice and Bob both initialize their SPAKE2 instances with the same (weak)
//! password. They will exchange messages to (hopefully) derive a shared secret
//! key.
//!
//! However, there are two roles in the SPAKE2 protocol, "A" and "B". The two
//! sides must agree ahead of time which one will play which role (the
//! messages they generate depend upon which side they play). There are two
//! separate constructor functions, `start_prover()` and `start_verifier()`, and a
//! complete interaction will use one of each (one `start_prover` on one computer,
//! and one `start_verifier` on the other computer).
//!
//! Each instance of a SPAKE2 protocol uses a set of shared parameters. These
//! include a group, a generator, and a pair of arbitrary group elements.
//! This library comes a single pre-generated parameter set, but could be
//! extended with others.
//!
//! You start by calling `start_prover()` (or `_b)` with the password and identity
//! strings for both sides. This gives you back a state object and the first
//! message, which you must send to your partner. Once you receive the
//! corresponding inbound message, you pass it into the state object
//! (consuming both in the process) by calling `s.finish()`, and you get back
//! the shared key as a bytestring.
//!
//! The password and identity strings must each be wrapped in a "newtype",
//! which is a simple `struct` that protects against swapping the different
//! types of bytestrings.
//!
//! Thus a client-side program start with:
//!
//! ```rust
//! use spake2r::{Ed25519Group, Identity, Password, prover::Prover, verifier::Verifier};
//! # fn send(msg: &[u8]) {}
//! let (prover, outbound_msg) = Prover::<Ed25519Group>::start(
//!    &Password::new(b"password"),
//!    &Identity::new(b"client id string"),
//!    &Identity::new(b"server id string"));
//! send(&outbound_msg);
//!
//! # fn receive() -> Vec<u8> { let (verifier, i2) = Verifier::<Ed25519Group>::start(&Password::new(b"password"), &Identity::new(b"client id string"), &Identity::new(b"server id string")); i2 }
//! let inbound_msg = receive();
//! let key1 = prover.finish(&inbound_msg).unwrap();
//! ```
//!
//! while the server-side might do:
//!
//! ```rust
//! # fn send(msg: &[u8]) {}
//! use spake2r::{Ed25519Group, Identity, Password, prover::Prover, verifier::Verifier};
//! let (verifier, outbound_msg) = Verifier::<Ed25519Group>::start(
//!    &Password::new(b"password"),
//!    &Identity::new(b"client id string"),
//!    &Identity::new(b"server id string"));
//! send(&outbound_msg);
//!
//! # fn receive() -> Vec<u8> { let (prover, i2) = Prover::<Ed25519Group>::start(&Password::new(b"password"), &Identity::new(b"client id string"), &Identity::new(b"server id string")); i2 }
//! let inbound_msg = receive();
//! let key2 = verifier.finish(&inbound_msg).unwrap();
//! ```
//!
//! If both sides used the same password, and there is no man-in-the-middle,
//! then `key1` and `key2` will be identical. If not, the two sides will get
//! different keys. When one side encrypts with `key1`, and the other side
//! attempts to decrypt with `key2`, they'll get nothing but garbled noise.
//!
//! The shared key can be used as an HMAC key to provide data integrity on
//! subsequent messages, or as an authenticated-encryption key (e.g.
//! nacl.secretbox). It can also be fed into [HKDF][1] to derive other
//! session keys as necessary.
//!
//! The `SPAKE2` instances, and the messages they create, are single-use. Create
//! a new one for each new session. `finish` consumes the instance.
//!
//! # Identifier Strings
//!
//! The SPAKE2 protocol includes a pair of "identity strings" `idProver` and `idVerifier`
//! that are included in the final key-derivation hash. This binds the key to a
//! single pair of parties, or for some specific purpose.
//!
//! For example, when user "alice" logs into "example.com", both sides should set
//! `idProver = b"alice"` and `idVerifier = b"example.com"`. This prevents an attacker from
//! substituting messages from unrelated login sessions (other users on the same
//! server, or other servers for the same user).
//!
//! This also makes sure the session is established with the correct service. If
//! Alice has one password for "example.com" but uses it for both login and
//! file-transfer services, `idVerifier` should be different for the two services.
//! Otherwise if Alice is simultaneously connecting to both services, and
//! attacker could rearrange the messages and cause her login client to connect
//! to the file-transfer server, and vice versa.
//!
//! `idProver` and `idVerifier` must be bytestrings (slices of `<u8>`).
//!
//!
//! # Serialization
//!
//! Sometimes, you can't hold the SPAKE2 instance in memory for the whole
//! negotiation: perhaps all your program state is stored in a database, and
//! nothing lives in RAM for more than a few moments.
//!
//! Unfortunately the Rust implementation does not yet provide serialization
//! of the state object. A future version should correct this.
//!
//! # Security
//!
//! This library is probably not constant-time, and does not protect against
//! timing attacks. Do not allow attackers to measure how long it takes you
//! to create or respond to a message. This matters somewhat less for pairing
//! protocols, because their passwords are single-use randomly-generated
//! keys, so an attacker has much less to work with.
//!
//! This library depends upon a strong source of random numbers. Do not use it on
//! a system where os.urandom() is weak.
//!
//! # Speed
//!
//! To run the built-in speed tests, just run `cargo bench`.
//!
//! SPAKE2 consists of two phases, separated by a single message exchange.
//! The time these phases take is split roughly 50/50. On my 2.8GHz Core-i7
//! (i7-7600U) cpu, the built-in Ed25519Group parameters take about 112
//! microseconds for each phase, and the message exchanged is 33 bytes long.
//!
//! # Testing
//!
//! Run `cargo test` to run the built-in test suite.
//!
//! # History
//!
//! The protocol was described as "PAKE2" in ["cryptobook"] [2] from Dan Boneh
//! and Victor Shoup. This is a form of "SPAKE2", defined by Abdalla and
//! Pointcheval at [RSA 2005] [3]. Additional recommendations for groups and
//! distinguished elements were published in [Ladd's IETF draft] [4].
//!
//! The Ed25519 implementation uses code adapted from Daniel Bernstein (djb),
//! Matthew Dempsky, Daniel Holth, Ron Garret, with further optimizations by
//! Brian Warner[5]. The "arbitrary element" computation, which must be the same
//! for both participants, is from python-pure25519 version 0.5.
//!
//! The Boneh/Shoup chapter that defines PAKE2 also defines an augmented variant
//! named "PAKE2+", which changes one side (typically a server) to record a
//! derivative of the password instead of the actual password. In PAKE2+, a
//! server compromise does not immediately give access to the passwords: instead,
//! the attacker must perform an offline dictionary attack against the stolen
//! data before they can learn the passwords. PAKE2+ support is planned, but not
//! yet implemented.
//!
//! Brian Warner first wrote the Python version in July 2010. He wrote this
//! Rust version in in May 2017.
//!
//! ### footnotes
//!
//! [1]: https://tools.ietf.org/html/rfc5869 "HKDF"
//! [2]: http://crypto.stanford.edu/~dabo/cryptobook/  "cryptobook"
//! [3]: http://www.di.ens.fr/~pointche/Documents/Papers/2005_rsa.pdf "RSA 2005"
//! [4]: https://tools.ietf.org/html/draft-ladd-spake2-01 "Ladd's IETF draft"
//! [5]: https://github.com/warner/python-pure25519
//! [6]: http://eprint.iacr.org/2003/038.pdf "Pretty-Simple Password-Authenticated Key-Exchange Under Standard Assumptions"
//! [7]: https://moderncrypto.org/mail-archive/curves/2015/000419.html "PAKE questions"

#[allow(unused_imports)]
#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
#[cfg_attr(test, macro_use)]
extern crate std;

mod ed25519;
mod error;
mod group;
pub mod prover;
pub mod verifier;

pub use self::{
    ed25519::Ed25519Group,
    error::{Error, Result},
    group::Group,
    prover::Prover,
    verifier::Verifier,
};

use alloc::vec::Vec;
use core::{fmt, ops::Deref, str};
use curve25519_dalek::{edwards::EdwardsPoint as c2_Element, scalar::Scalar as c2_Scalar};

/// Password type.
// TODO(tarcieri): avoid allocation?
#[derive(PartialEq, Eq, Clone)]
pub struct Password(Vec<u8>);

impl Password {
    /// Create a new password.
    pub fn new(p: impl AsRef<[u8]>) -> Self {
        Self(p.as_ref().to_vec())
    }
}

impl Deref for Password {
    type Target = Vec<u8>;

    fn deref(&self) -> &Vec<u8> {
        &self.0
    }
}

/// SPake2r identity.
// TODO(tarcieri): avoid allocation?
#[derive(PartialEq, Eq, Clone)]
pub struct Identity(Vec<u8>);

impl Deref for Identity {
    type Target = Vec<u8>;

    fn deref(&self) -> &Vec<u8> {
        &self.0
    }
}

impl Identity {
    /// Create a new identity.
    #[must_use]
    pub fn new(p: &[u8]) -> Self {
        Self(p.to_vec())
    }
}

struct MaybeUtf8<'a>(&'a [u8]);

impl fmt::Debug for MaybeUtf8<'_> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Ok(s) = str::from_utf8(self.0) {
            write!(fmt, "(s={s})")
        } else {
            write!(fmt, "(hex=")?;

            for byte in self.0 {
                write!(fmt, "{byte:x}")?;
            }

            write!(fmt, ")")
        }
    }
}

/// This compares results against the python compatibility tests:
/// spake2r.test.test_compat.SPake2r.test_asymmetric . The python test passes a
/// deterministic RNG (used only for tests, of course) into the per-Group
/// "random_scalar()" function, which results in some particular scalar.
#[cfg(all(test, feature = "std"))]
mod tests {
    use crate::*;
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
    use num_bigint::BigUint;

    // the python tests show the long-integer form of scalars. the rust code
    // wants an array of bytes (little-endian). Make sure the way we convert
    // things works correctly.
    fn decimal_to_scalar(d: &[u8]) -> c2_Scalar {
        let bytes = BigUint::parse_bytes(d, 10).unwrap().to_bytes_le();
        assert_eq!(bytes.len(), 32);
        let mut b2 = [0u8; 32];
        b2.copy_from_slice(&bytes);
        c2_Scalar::from_bytes_mod_order(b2)
    }

    #[test]
    fn test_convert() {
        let t1_decimal =
            b"2238329342913194256032495932344128051776374960164957527413114840482143558222";
        let t1_scalar = decimal_to_scalar(t1_decimal);
        let t1_bytes = t1_scalar.to_bytes();
        let expected = [
            0x4e, 0x5a, 0xb4, 0x34, 0x5d, 0x47, 0x08, 0x84, 0x59, 0x13, 0xb4, 0x64, 0x1b, 0xc2,
            0x7d, 0x52, 0x52, 0xa5, 0x85, 0x10, 0x1b, 0xcc, 0x42, 0x44, 0xd4, 0x49, 0xf4, 0xa8,
            0x79, 0xd9, 0xf2, 0x04,
        ];
        assert_eq!(t1_bytes, expected);
        //println!("t1_scalar is {:?}", t1_scalar);
    }

    #[test]
    fn test_serialize_basepoint() {
        // make sure elements are serialized same as the python library
        let exp = "5866666666666666666666666666666666666666666666666666666666666666";
        let base_vec = ED25519_BASEPOINT_POINT.compress().as_bytes().to_vec();
        let base_hex = hex::encode(base_vec);
        println!("exp: {:?}", exp);
        println!("got: {:?}", base_hex);
        assert_eq!(exp, base_hex);
    }

    #[test]
    fn test_password_to_scalar() {
        let password = Password::new(b"password");
        let expected_pw_scalar = decimal_to_scalar(
            b"3515301705789368674385125653994241092664323519848410154015274772661223168839",
        );
        let pw_scalar = Ed25519Group::hash_to_scalar(&password);
        println!("exp: {:?}", hex::encode(expected_pw_scalar.as_bytes()));
        println!("got: {:?}", hex::encode(pw_scalar.as_bytes()));
        assert_eq!(&pw_scalar, &expected_pw_scalar);
    }

    #[test]
    fn test_sizes() {
        let (prover, msg1) = Prover::<Ed25519Group>::start(
            &Password::new(b"password"),
            &Identity::new(b"idProver"),
            &Identity::new(b"idVerifier"),
        );
        assert_eq!(msg1.len(), 1 + 32);
        let (verifier, msg2) = Verifier::<Ed25519Group>::start(
            &Password::new(b"password"),
            &Identity::new(b"idProver"),
            &Identity::new(b"idVerifier"),
        );
        assert_eq!(msg2.len(), 1 + 32);
        let key1 = prover.finish(&msg2).unwrap();
        let key2 = verifier.finish(&msg1).unwrap();
        assert_eq!(key1.len(), 32);
        assert_eq!(key2.len(), 32);
    }

    #[test]
    fn test_hash_identites() {
        let key = Ed25519Group::hash_identities(
            b"pw",
            b"idA",
            b"idB",
            b"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", // len=32
            b"YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY",
            b"KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK",
        );
        let expected_key = "d59d9ba920f7092565cec747b08d5b2e981d553ac32fde0f25e5b4a4cfca3efd";
        assert_eq!(hex::encode(key), expected_key);
    }

    #[test]
    fn test_asymmetric() {
        let scalar_prover = decimal_to_scalar(
            b"2611694063369306139794446498317402240796898290761098242657700742213257926693",
        );
        let scalar_verifier = decimal_to_scalar(
            b"7002393159576182977806091886122272758628412261510164356026361256515836884383",
        );
        let expected_pw_scalar = decimal_to_scalar(
            b"3515301705789368674385125653994241092664323519848410154015274772661223168839",
        );

        println!("scalar_prover is {}", hex::encode(scalar_prover.as_bytes()));

        let (prover, msg1) = Prover::<Ed25519Group>::start_deterministic(
            &Password::new(b"password"),
            &Identity::new(b"idA"),
            &Identity::new(b"idB"),
            scalar_prover,
        );
        let expected_msg1 = "416fc960df73c9cf8ed7198b0c9534e2e96a5984bfc5edc023fd24dacf371f2af9";

        println!();
        println!("x: {:?}", hex::encode(prover.x.as_bytes()));
        println!();
        println!(
            "pw_prover: {:?}",
            hex::encode(prover.password_scalar.as_bytes())
        );
        println!("exp : {:?}", hex::encode(expected_pw_scalar.as_bytes()));
        println!();
        println!("msg1: {:?}", hex::encode(&msg1));
        println!("exp : {:?}", expected_msg1);
        println!();

        assert_eq!(
            hex::encode(expected_pw_scalar.as_bytes()),
            hex::encode(prover.password_scalar.as_bytes())
        );
        assert_eq!(hex::encode(&msg1), expected_msg1);

        let (verifier, msg2) = Verifier::<Ed25519Group>::start_deterministic(
            &Password::new(b"password"),
            &Identity::new(b"idA"),
            &Identity::new(b"idB"),
            scalar_verifier,
        );
        assert_eq!(expected_pw_scalar, verifier.password_scalar);
        assert_eq!(
            hex::encode(&msg2),
            "42354e97b88406922b1df4bea1d7870f17aed3dba7c720b313edae315b00959309"
        );

        let key1 = prover.finish(&msg2).unwrap();
        let key2 = verifier.finish(&msg1).unwrap();
        assert_eq!(key1, key2);
        assert_eq!(
            hex::encode(key1),
            "712295de7219c675ddd31942184aa26e0a957cf216bc230d165b215047b520c1"
        );
    }

    #[test]
    fn test_debug() {
        let (prover, _msg1) = Prover::<Ed25519Group>::start(
            &Password::new(b"password"),
            &Identity::new(b"idProver"),
            &Identity::new(b"idVerifier"),
        );
        println!("prover: {:?}", prover);
        assert_eq!(
            format!("{:?}", prover),
            "Prover { group: \"Ed25519\", idProver: (s=idProver), idVerifier: (s=idVerifier) }"
        );

        let (verifier, _msg1) = Verifier::<Ed25519Group>::start(
            &Password::new(b"password"),
            &Identity::new(b"idProver"),
            &Identity::new(b"idVerifier"),
        );
        println!("verifier: {:?}", verifier);
        assert_eq!(
            format!("{:?}", verifier),
            "Verifier { group: \"Ed25519\", idProver: (s=idProver), idVerifier: (s=idVerifier) }"
        );
    }
}
