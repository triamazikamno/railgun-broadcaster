use alloy::primitives::U256;
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use merkletree::tree::{MerkleTree, bench_compute_root_alloc, bench_hash_layer_alloc};
use rayon::ThreadPoolBuilder;

const INPUT_SIZE: usize = 1 << 15;
const THREADS: usize = 4;

fn build_layer() -> Vec<U256> {
    (0..INPUT_SIZE as u64).map(U256::from).collect()
}

fn build_tree() -> MerkleTree {
    let mut tree = MerkleTree::default();
    for index in 0..INPUT_SIZE as u64 {
        let _ = tree.insert(index, U256::from(index));
    }
    tree
}

fn bench_hash_layer(c: &mut Criterion) {
    let pool = ThreadPoolBuilder::new()
        .num_threads(THREADS)
        .build()
        .expect("rayon thread pool");

    let mut group = c.benchmark_group("hash_layer");
    group
        .measurement_time(std::time::Duration::from_secs(10))
        .sample_size(60);
    group.bench_function("alloc", |b| {
        b.iter_batched(
            build_layer,
            |mut layer| {
                pool.install(|| bench_hash_layer_alloc(&mut layer));
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();

    let mut root_group = c.benchmark_group("compute_root");
    root_group
        .measurement_time(std::time::Duration::from_secs(10))
        .sample_size(30);
    let tree = build_tree();
    root_group.bench_function("alloc", |b| {
        b.iter_batched(
            || &tree,
            |tree| {
                pool.install(|| {
                    let _ = bench_compute_root_alloc(tree);
                });
            },
            BatchSize::SmallInput,
        );
    });

    root_group.finish();
}

criterion_group!(benches, bench_hash_layer);
criterion_main!(benches);
