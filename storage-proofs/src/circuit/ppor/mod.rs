use std::marker::PhantomData;

use bellman::{Circuit, ConstraintSystem, SynthesisError};
use sapling_crypto::circuit::{boolean, multipack, num};
use sapling_crypto::jubjub::JubjubEngine;

use circuit::constraint;
use hasher::{HashFunction, Hasher};

/// This is an instance of the `ParallelProofOfRetrievability` circuit.
///
/// # Public Inputs
///
/// This circuit expects the following public inputs.
///
/// * for i in 0..values.len()
///   * [0] - packed version of `value` as bits. (might be more than one Fr)
///   * [1] - packed version of the `is_right` components of the auth_path.
///   * [2] - the merkle root of the tree.
pub struct ParallelProofOfRetrievability<'a, E: JubjubEngine, H: Hasher> {
    /// Paramters for the engine.
    pub params: &'a E::Params,

    /// Pedersen commitment to the value.
    pub values: Vec<Option<E::Fr>>,

    /// The authentication path of the commitment in the tree.
    pub auth_paths: Vec<Vec<Option<(E::Fr, bool)>>>,

    /// The root of the underyling merkle tree.
    pub root: Option<E::Fr>,

    _h: PhantomData<H>,
}

impl<'a, E: JubjubEngine, H: Hasher> Circuit<E> for ParallelProofOfRetrievability<'a, E, H> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        assert_eq!(self.values.len(), self.auth_paths.len());

        let real_root_value = self.root;

        // Allocate the "real" root that will be exposed.
        let rt = num::AllocatedNum::alloc(cs.namespace(|| "root value"), || {
            real_root_value.ok_or(SynthesisError::AssignmentMissing)
        })?;

        for i in 0..self.values.len() {
            let mut cs = cs.namespace(|| format!("round {}", i));
            let params = self.params;
            let value = self.values[i];
            let auth_path = self.auth_paths[i].clone();

            let value_num = num::AllocatedNum::alloc(cs.namespace(|| "value"), || {
                value.ok_or_else(|| SynthesisError::AssignmentMissing)
            })?;

            value_num.inputize(cs.namespace(|| "value num"))?;

            // This is an injective encoding, as cur is a
            // point in the prime order subgroup.
            let mut cur = value_num;

            let mut auth_path_bits = Vec::with_capacity(auth_path.len());

            // Ascend the merkle tree authentication path
            for (i, e) in auth_path.into_iter().enumerate() {
                let cs = &mut cs.namespace(|| format!("merkle tree hash {}", i));

                // Determines if the current subtree is the "right" leaf at this
                // depth of the tree.
                let cur_is_right = boolean::Boolean::from(boolean::AllocatedBit::alloc(
                    cs.namespace(|| "position bit"),
                    e.map(|e| e.1),
                )?);

                // Witness the authentication path element adjacent
                // at this depth.
                let path_element =
                    num::AllocatedNum::alloc(cs.namespace(|| "path element"), || {
                        Ok(e.ok_or(SynthesisError::AssignmentMissing)?.0)
                    })?;

                // Swap the two if the current subtree is on the right
                let (xl, xr) = num::AllocatedNum::conditionally_reverse(
                    cs.namespace(|| "conditional reversal of preimage"),
                    &cur,
                    &path_element,
                    &cur_is_right,
                )?;

                let xl_bits = xl.into_bits_le(cs.namespace(|| "xl into bits"))?;
                let xr_bits = xr.into_bits_le(cs.namespace(|| "xr into bits"))?;

                // Compute the new subtree value
                cur = H::Function::hash_node_circuit::<E, _>(
                    cs.namespace(|| "computation of pedersen hash"),
                    xl_bits,
                    xr_bits,
                    i,
                    params,
                )?;

                auth_path_bits.push(cur_is_right);
            }

            // allocate input for is_right auth_path
            multipack::pack_into_inputs(cs.namespace(|| "packed auth_path"), &auth_path_bits)?;

            {
                // Validate that the root of the merkle tree that we calculated is the same as the input.
                constraint::equal(&mut cs, || "enforce root is correct", &cur, &rt);
            }
        }

        // Expose the root
        rt.inputize(cs.namespace(|| "root"))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use pairing::bls12_381::*;
    use pairing::Field;
    use rand::{Rng, SeedableRng, XorShiftRng};
    use sapling_crypto::jubjub::JubjubBls12;

    use circuit::test::*;
    use drgraph::{new_seed, BucketGraph, Graph};
    use fr32::{bytes_into_fr, fr_into_bytes};
    use hasher::{Blake2sHasher, Hasher, PedersenHasher};
    use merklepor;
    use proof::ProofScheme;

    use util::data_at_node;

    #[test]
    fn parallel_por_input_circuit_with_bls12_381_pedersen() {
        test_parallel_por_input_circuit_with_bls12_381::<PedersenHasher>(88497);
    }

    #[test]
    fn parallel_por_input_circuit_with_bls12_381_blake2s() {
        test_parallel_por_input_circuit_with_bls12_381::<Blake2sHasher>(2750449);
    }

    fn test_parallel_por_input_circuit_with_bls12_381<H: Hasher>(num_constraints: usize) {
        let params = &JubjubBls12::new();
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let leaves = 16;
        let lambda = 32;
        let pub_params = merklepor::PublicParams { lambda, leaves };

        for _ in 0..1
        /* 5*/
        {
            let data: Vec<u8> = (0..leaves)
                .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
                .collect();

            let graph = BucketGraph::<H>::new(leaves, 6, 0, new_seed());
            let tree = graph.merkle_tree(data.as_slice(), lambda).unwrap();

            let pub_inputs: Vec<_> = (0..leaves)
                .map(|i| merklepor::PublicInputs {
                    challenge: i,
                    commitment: Some(tree.root()),
                })
                .collect();
            let priv_inputs: Vec<_> = (0..leaves)
                .map(|i| {
                    merklepor::PrivateInputs::<H>::new(
                        bytes_into_fr::<Bls12>(
                            data_at_node(
                                data.as_slice(),
                                pub_inputs[i].challenge,
                                pub_params.lambda,
                            )
                            .unwrap(),
                        )
                        .unwrap()
                        .into(),
                        &tree,
                    )
                })
                .collect();

            let proofs: Vec<_> = (0..leaves)
                .map(|i| {
                    merklepor::MerklePoR::<H>::prove(&pub_params, &pub_inputs[i], &priv_inputs[i])
                        .unwrap()
                })
                .collect();

            for i in 0..leaves {
                // make sure it verifies
                assert!(
                    merklepor::MerklePoR::<H>::verify(&pub_params, &pub_inputs[i], &proofs[i])
                        .unwrap(),
                    "failed to verify merklepor proof"
                );
            }

            let auth_paths: Vec<_> = proofs.iter().map(|p| p.proof.as_options()).collect();
            let values: Vec<_> = proofs.iter().map(|p| Some(p.data.into())).collect();

            let mut cs = TestConstraintSystem::<Bls12>::new();

            let instance = ParallelProofOfRetrievability::<_, H> {
                params,
                values,
                auth_paths,
                root: Some(tree.root().into()),
                _h: PhantomData,
            };

            instance
                .synthesize(&mut cs)
                .expect("failed to synthesize circuit");

            if !cs.is_satisfied() {
                println!("not satisfied: {:?}", cs.which_is_unsatisfied());
                panic!("constraints not satisfied");
            }
            // assert!(cs.is_satisfied(), "constraints not satisfied");

            assert_eq!(cs.num_inputs(), 34, "wrong number of inputs");
            assert_eq!(cs.get_input(0, "ONE"), Fr::one());

            assert_eq!(
                cs.num_constraints(),
                num_constraints,
                "wrong number of constraints"
            );
        }
    }
}
