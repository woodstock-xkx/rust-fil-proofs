extern crate bellman;
extern crate pairing;
extern crate pbr;
extern crate rand;
extern crate sapling_crypto;

extern crate storage_proofs;

use bellman::groth16::*;
use bellman::{Circuit, ConstraintSystem, SynthesisError};
use pairing::bls12_381::{Bls12, Fr};
use pairing::PrimeField;
use rand::Rng;
use sapling_crypto::circuit::{boolean, num, pedersen_hash};
use sapling_crypto::jubjub::{JubjubBls12, JubjubEngine};

use storage_proofs::example_helper::Example;

// TODO: figure out how to make this dynamic on the inputs
const NUM_VALUES: usize = 100;

struct InputsFixed<'a, E: JubjubEngine> {
    params: &'a E::Params,
}

impl<'a> Circuit<Bls12> for InputsFixed<'a, Bls12> {
    fn synthesize<CS: ConstraintSystem<Bls12>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let values = (0..NUM_VALUES).map(|i| Fr::from_repr((i as u64).into()).unwrap());

        for (i, value) in values.enumerate() {
            let cs = &mut cs.namespace(|| format!("{}", i));

            let value_num = num::AllocatedNum::alloc(cs.namespace(|| "value"), || Ok(value))?;

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
struct InputsFixedApp {}

impl<'a> Example<'a, InputsFixed<'a, Bls12>> for InputsFixedApp {
    fn name() -> String {
        "InputsFixed".to_string()
    }

    fn generate_groth_params<R: Rng>(
        &mut self,
        rng: &mut R,
        jubjub_params: &'a JubjubBls12,
        _tree_depth: usize,
        _challenge_count: usize,
        _lambda: usize,
        _m: usize,
        _sloth_iter: usize,
    ) -> Parameters<Bls12> {
        generate_random_parameters::<Bls12, _, _>(
            InputsFixed {
                params: jubjub_params,
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
        _rng: &mut R,
        engine_params: &'a JubjubBls12,
        _tree_depth: usize,
        _challenge_count: usize,
        _leaves: usize,
        _lambda: usize,
        _m: usize,
        _sloth_iter: usize,
    ) -> InputsFixed<'a, Bls12> {
        InputsFixed {
            params: engine_params,
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
    InputsFixedApp::main()
}
