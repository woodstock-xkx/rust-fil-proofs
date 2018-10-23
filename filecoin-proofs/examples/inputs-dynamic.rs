extern crate bellman;
extern crate pairing;
extern crate pbr;
extern crate rand;
extern crate sapling_crypto;

extern crate storage_proofs;

use bellman::groth16::*;
use bellman::{Circuit, ConstraintSystem, SynthesisError};
use pairing::bls12_381::Bls12;
use rand::Rng;
use sapling_crypto::circuit::{boolean, num, pedersen_hash};
use sapling_crypto::jubjub::{JubjubBls12, JubjubEngine};

use storage_proofs::example_helper::Example;

struct InputsDynamic<'a, E: JubjubEngine> {
    params: &'a E::Params,
    values: Vec<Option<E::Fr>>,
}

impl<'a> Circuit<Bls12> for InputsDynamic<'a, Bls12> {
    fn synthesize<CS: ConstraintSystem<Bls12>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        for (i, value) in self.values.iter().enumerate() {
            let cs = &mut cs.namespace(|| format!("{}", i));

            let value_num = num::AllocatedNum::alloc(cs.namespace(|| "value"), || {
                Ok(value.ok_or_else(|| SynthesisError::AssignmentMissing)?)
            })?;
            value_num.inputize(cs.namespace(|| "input"))?;

            let mut value_bits = value_num.into_bits_le(cs.namespace(|| "value bits"))?;

            // sad face, need to pad to make all algorithms the same
            while value_bits.len() < 256 {
                value_bits.push(boolean::Boolean::Constant(false));
            }

            // Compute the hash of the value
            pedersen_hash::pedersen_hash(
                cs.namespace(|| "value hash"),
                pedersen_hash::Personalization::NoteCommitment,
                &value_bits,
                self.params,
            )?;
        }

        Ok(())
    }
}

#[derive(Default)]
struct InputsDynamicApp {}

impl<'a> Example<'a, InputsDynamic<'a, Bls12>> for InputsDynamicApp {
    fn name() -> String {
        "InputsDynamic".to_string()
    }

    fn generate_groth_params<R: Rng>(
        &mut self,
        rng: &mut R,
        jubjub_params: &'a JubjubBls12,
        _tree_depth: usize,
        challenge_count: usize,
        _lambda: usize,
        _m: usize,
        _sloth_iter: usize,
    ) -> Parameters<Bls12> {
        generate_random_parameters::<Bls12, _, _>(
            InputsDynamic {
                params: jubjub_params,
                values: vec![None; challenge_count],
            },
            rng,
        )
        .unwrap()
    }

    fn samples() -> usize {
        5
    }

    fn create_circuit<R: Rng>(
        &mut self,
        rng: &mut R,
        engine_params: &'a JubjubBls12,
        _tree_depth: usize,
        challenge_count: usize,
        _leaves: usize,
        _lambda: usize,
        _m: usize,
        _sloth_iter: usize,
    ) -> InputsDynamic<'a, Bls12> {
        InputsDynamic {
            params: engine_params,
            values: (0..challenge_count).map(|_| Some(rng.gen())).collect(),
        }
    }

    fn verify_proof(
        &mut self,
        _proof: &Proof<Bls12>,
        _pvk: &PreparedVerifyingKey<Bls12>,
    ) -> Option<bool> {
        // not implemented yet
        None
    }
}

fn main() {
    InputsDynamicApp::main()
}
