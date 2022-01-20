use simple_rijndael::tests;

use criterion::{criterion_group, criterion_main, Criterion};

fn osu_decrypt_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("osu_decrypt_benchmark");
    group.bench_function("osu decrypt", move |b| b.iter(|| tests::osu_dec().unwrap()));
    group.finish();
}

fn osu_encrypt_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("osu_encrypt_benchmark");
    group.bench_function("osu encrypt", |b| b.iter(|| tests::osu_enc().unwrap()));
    group.finish();
}

criterion_group!(benches, osu_encrypt_benchmark, osu_decrypt_benchmark);
criterion_main!(benches);
