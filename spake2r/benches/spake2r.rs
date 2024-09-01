use bencher::Bencher;
use bencher::{benchmark_group, benchmark_main};
use spake2r::{prover::Prover, verifier::Verifier, Ed25519Group, Identity, Password};

fn spake2r_start_prover(bench: &mut Bencher) {
    bench.iter(|| {
        let (_, _) = Prover::<Ed25519Group>::start(
            &Password::new(b"password"),
            &Identity::new(b"idProver"),
            &Identity::new(b"idVerifier"),
        );
    })
}
fn spake2r_start_verifier(bench: &mut Bencher) {
    bench.iter(|| {
        let (_, _) = Verifier::<Ed25519Group>::start(
            &Password::new(b"password"),
            &Identity::new(b"idProver"),
            &Identity::new(b"idVerifier"),
        );
    })
}

/*
fn spake2r_finish(bench: &mut Bencher) {
    // this doesn't work, because s1 is consumed by doing finish()
    let (s1, msg1) = SPake2r::<Ed25519Group>::start_prover(
        &Password::new(b"password"),
        &Identity::new(b"idProver"),
        &Identity::new(b"idVerifier"),
    );
    let (s2, msg2) = SPake2r::<Ed25519Group>::start_verifier(
        &Password::new(b"password"),
        &Identity::new(b"idProver"),
        &Identity::new(b"idVerifier"),
    );
    let msg2_slice = msg2.as_slice();
    bench.iter(|| s1.finish(msg2_slice))
}
*/

fn spake2r_start_prover_and_finish(bench: &mut Bencher) {
    let (_, msg2) = Verifier::<Ed25519Group>::start(
        &Password::new(b"password"),
        &Identity::new(b"idProver"),
        &Identity::new(b"idVerifier"),
    );
    let msg2_slice = msg2.as_slice();
    bench.iter(|| {
        let (prover, _) = Prover::<Ed25519Group>::start(
            &Password::new(b"password"),
            &Identity::new(b"idProver"),
            &Identity::new(b"idVerifier"),
        );
        prover.finish(msg2_slice)
    })
}

benchmark_group!(
    benches,
    spake2r_start_verifier,
    spake2r_start_prover,
    //spake2r_finish,
    spake2r_start_prover_and_finish
);
benchmark_main!(benches);
