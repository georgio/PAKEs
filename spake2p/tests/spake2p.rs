use spake2p::{Ed25519Group, Error, Identity, Password, Spake2p};

#[test]
fn test_basic() {
    let (s1, msg1) = Spake2p::<Ed25519Group>::start_prover(
        &Password::new(b"password"),
        &Identity::new(b"idProver"),
        &Identity::new(b"idVerifier"),
    );
    let (s2, msg2) = Spake2p::<Ed25519Group>::start_verifier(
        &Password::new(b"password"),
        &Identity::new(b"idProver"),
        &Identity::new(b"idVerifier"),
    );
    let key1 = s1.finish(msg2.as_slice()).unwrap();
    let key2 = s2.finish(msg1.as_slice()).unwrap();
    assert_eq!(key1, key2);
}

#[test]
fn test_mismatch() {
    let (s1, msg1) = Spake2p::<Ed25519Group>::start_prover(
        &Password::new(b"password"),
        &Identity::new(b"idProver"),
        &Identity::new(b"idVerifier"),
    );
    let (s2, msg2) = Spake2p::<Ed25519Group>::start_verifier(
        &Password::new(b"password2"),
        &Identity::new(b"idProver"),
        &Identity::new(b"idVerifier"),
    );
    let key1 = s1.finish(msg2.as_slice()).unwrap();
    let key2 = s2.finish(msg1.as_slice()).unwrap();
    assert_ne!(key1, key2);
}

#[test]
fn test_reflected_message() {
    let (s1, msg1) = Spake2p::<Ed25519Group>::start_prover(
        &Password::new(b"password"),
        &Identity::new(b"idProver"),
        &Identity::new(b"idVerifier"),
    );
    let r = s1.finish(msg1.as_slice());
    assert_eq!(r.unwrap_err(), Error::BadSide);
}

#[test]
#[allow(clippy::slow_vector_initialization)]
fn test_bad_length() {
    let (s1, msg1) = Spake2p::<Ed25519Group>::start_prover(
        &Password::new(b"password"),
        &Identity::new(b"idProver"),
        &Identity::new(b"idVerifier"),
    );
    let mut msg2 = Vec::<u8>::with_capacity(msg1.len() + 1);
    msg2.resize(msg1.len() + 1, 0u8);
    let r = s1.finish(&msg2);
    assert_eq!(r.unwrap_err(), Error::WrongLength);
}
