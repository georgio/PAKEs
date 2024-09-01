use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use spake2r::{prover::Prover, verifier::Verifier, Ed25519Group, Identity, Password};

fn spake2r_start_prover(c: &mut Criterion) {
    c.bench_function("spake2r_start_prover", |b| {
        b.iter(|| {
            Prover::<Ed25519Group>::start(
                &Password::new(b"password"),
                &Identity::new(b"idProver"),
                &Identity::new(b"idVerifier"),
            )
        })
    });
}

fn spake2r_start_verifier(c: &mut Criterion) {
    c.bench_function("spake2r_start_verifier", |b| {
        b.iter(|| {
            Verifier::<Ed25519Group>::start(
                &Password::new(b"password"),
                &Identity::new(b"idProver"),
                &Identity::new(b"idVerifier"),
            )
        })
    });
}

fn spake2r_finish(c: &mut Criterion) {
    // this doesn't work, because s1 is consumed by doing finish()

    c.bench_function("spake2r_start_verifier", |b| {
        b.iter_batched(
            || {
                let pwd = &Password::new(b"password");
                let id_prover = &Identity::new(b"idProver");
                let id_verifier = &Identity::new(b"idVerifier");

                let (prover, _msg1) = Prover::<Ed25519Group>::start(pwd, id_prover, id_verifier);
                let (_verifier, msg2) =
                    Verifier::<Ed25519Group>::start(pwd, id_prover, id_verifier);
                (prover, msg2)
            },
            |(prvr, msg2)| prvr.finish(msg2.as_slice()),
            BatchSize::PerIteration,
        )
    });
}

fn spake2r_start_prover_and_finish(c: &mut Criterion) {
    c.bench_function("spake2r_start_prover_and_finish", |b| {
        b.iter_batched(
            || {
                let pwd = Password::new(b"password");
                let id_prover = Identity::new(b"idProver");
                let id_verifier = Identity::new(b"idVerifier");

                let (_verifier, msg2) =
                    Verifier::<Ed25519Group>::start(&pwd, &id_prover, &id_verifier);
                (pwd, id_prover, id_verifier, msg2)
            },
            |(pwd, id_prover, id_verifier, msg2)| {
                let (prover, _msg1) = Prover::<Ed25519Group>::start(&pwd, &id_prover, &id_verifier);
                prover.finish(msg2.as_slice())
            },
            BatchSize::PerIteration,
        )
    });
}

criterion_group!(
    benches,
    spake2r_start_verifier,
    spake2r_start_prover,
    spake2r_finish,
    spake2r_start_prover_and_finish
);
criterion_main!(benches);
