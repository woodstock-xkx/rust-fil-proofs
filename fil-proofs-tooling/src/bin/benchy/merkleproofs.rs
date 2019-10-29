use log::info;
use merkletree::merkle::{FromIndexedParallelIterator, MerkleTree};
use merkletree::store::DiskStore;
use rand::{Rng, SeedableRng, XorShiftRng};
use rayon::prelude::*;
use storage_proofs::hasher::{Hasher, PedersenHasher};
use storage_proofs::util::NODE_SIZE;

fn generate_tree<R: Rng>(
    rng: &mut R,
    size: usize,
) -> MerkleTree<
    <PedersenHasher as Hasher>::Domain,
    <PedersenHasher as Hasher>::Function,
    DiskStore<<PedersenHasher as Hasher>::Domain>,
> {
    let el: <PedersenHasher as Hasher>::Domain = rng.gen();
    info!("create tree {} KiB", (size * NODE_SIZE) / 1024);
    MerkleTree::from_par_iter((0..size).into_par_iter().map(|_| el.clone()))
}

pub fn run(size: usize, proofs_count: usize) -> Result<(), failure::Error> {
    let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    let nodes = size / NODE_SIZE;
    let tree = generate_tree(&mut rng, nodes);

    info!("creating {} inclusion proofs", proofs_count);

    let mut proofs = Vec::with_capacity(proofs_count);
    for _ in 0..proofs_count {
        let challenge = rng.gen_range(0, nodes);

        proofs.push(tree.gen_proof(challenge));
    }
    assert_eq!(proofs.len(), proofs_count);

    info!("proofs created");

    Ok(())
}
