//! Micro-benchmarks for the hot paths: entropy computation and SHA-256.

use aegis_engine::{sha256_hex, shannon_entropy};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

fn bench_entropy(c: &mut Criterion) {
    let mut group = c.benchmark_group("shannon_entropy");
    for size in [4 * 1024usize, 64 * 1024, 1024 * 1024] {
        let data: Vec<u8> = (0..size).map(|i| (i * 31 + 7) as u8).collect();
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, d| {
            b.iter(|| shannon_entropy(d))
        });
    }
    group.finish();
}

fn bench_sha256(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha256");
    for size in [4 * 1024usize, 1024 * 1024] {
        let data = vec![0xABu8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, d| {
            b.iter(|| sha256_hex(d))
        });
    }
    group.finish();
}

criterion_group!(benches, bench_entropy, bench_sha256);
criterion_main!(benches);
