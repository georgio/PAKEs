use bencher::Bencher;
use bencher::{benchmark_group, benchmark_main};
use spake2p::{Ed25519Group, Identity, Password, Spake2p};

fn spake2p_start(bench: &mut Bencher) {
    bench.iter(|| {
        let (_, _) = Spake2p::<Ed25519Group>::start_prover(
            &Password::new(b"password"),
            &Identity::new(b"idProver"),
            &Identity::new(b"idVerifier"),
        );
    })
}

/*
fn spake2p_finish(bench: &mut Bencher) {
    // this doesn't work, because s1 is consumed by doing finish()
    let (s1, msg1) = SPAKE2p::<Ed25519Group>::start_prover(
        &Password::new(b"password"),
        &Identity::new(b"idProver"),
        &Identity::new(b"idVerifier"),
    );
    let (s2, msg2) = SPAKE2p::<Ed25519Group>::start_verifier(
        &Password::new(b"password"),
        &Identity::new(b"idProver"),
        &Identity::new(b"idVerifier"),
    );
    let msg2_slice = msg2.as_slice();
    bench.iter(|| s1.finish(msg2_slice))
}
*/

fn spake2p_start_provernd_finish(bench: &mut Bencher) {
    let (_, msg2) = Spake2p::<Ed25519Group>::start_verifier(
        &Password::new(b"password"),
        &Identity::new(b"idProver"),
        &Identity::new(b"idVerifier"),
    );
    let msg2_slice = msg2.as_slice();
    bench.iter(|| {
        let (s1, _) = Spake2p::<Ed25519Group>::start_prover(
            &Password::new(b"password"),
            &Identity::new(b"idProver"),
            &Identity::new(b"idVerifier"),
        );
        s1.finish(msg2_slice)
    })
}

benchmark_group!(
    benches,
    spake2p_start,
    //spake2p_finish,
    spake2p_start_provernd_finish
);
benchmark_main!(benches);
