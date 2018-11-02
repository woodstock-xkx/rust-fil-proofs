use std::fmt;
use std::hash::Hasher as StdHasher;
use std::marker::PhantomData;

use bellman::{ConstraintSystem, SynthesisError};
use byteorder::{LittleEndian, WriteBytesExt};
use merkle_light::hash::{Algorithm, Hashable};
use pairing::bls12_381::{Bls12, Fr, FrRepr};
use pairing::{PrimeField, PrimeFieldRepr};
use rand::{Rand, Rng};
use sapling_crypto::circuit::blake2s::blake2s as blake2s_circuit;
use sapling_crypto::circuit::boolean::{AllocatedBit, Boolean};
use sapling_crypto::circuit::multipack;
use sapling_crypto::circuit::num::AllocatedNum;
use sapling_crypto::jubjub::JubjubEngine;
use sha2::Digest;

use super::{Domain, HashFunction, Hasher};
use crypto::sloth;
use error::*;

pub trait Digester: Digest + Clone + Default + ::std::fmt::Debug + Send + Sync {}

#[derive(Default, Copy, Clone, Debug)]
pub struct DigestHasher<D: Digester> {
    _d: PhantomData<D>,
}

impl<D: Digester> PartialEq for DigestHasher<D> {
    fn eq(&self, other: &Self) -> bool {
        self._d == other._d
    }
}

impl<D: Digester> Eq for DigestHasher<D> {}

impl<D: Digester> Hasher for DigestHasher<D> {
    type Domain = DigestDomain;
    type Function = DigestFunction<D>;

    fn kdf(data: &[u8], m: usize) -> Self::Domain {
        assert_eq!(
            data.len(),
            32 * (1 + m),
            "invalid input length: data.len(): {} m: {}",
            data.len(),
            m
        );

        let mut res = <Self::Function as HashFunction<Self::Domain>>::hash(data);
        // strip last two bits, to make them stay in Fr
        res.0[31] &= 0b0011_1111;

        res
    }

    fn sloth_encode(key: &Self::Domain, ciphertext: &Self::Domain, rounds: usize) -> Self::Domain {
        // TODO: validate this is how sloth should work in this case
        let k = (*key).into();
        let c = (*ciphertext).into();

        sloth::encode::<Bls12>(&k, &c, rounds).into()
    }

    fn sloth_decode(key: &Self::Domain, ciphertext: &Self::Domain, rounds: usize) -> Self::Domain {
        // TODO: validate this is how sloth should work in this case
        sloth::decode::<Bls12>(&(*key).into(), &(*ciphertext).into(), rounds).into()
    }
}

#[derive(Default, Clone)]
pub struct DigestFunction<D: Digester>(D);

impl<D: Digester> PartialEq for DigestFunction<D> {
    fn eq(&self, other: &Self) -> bool {
        format!("{:?}", self) == format!("{:?}", other)
    }
}

impl<D: Digester> Eq for DigestFunction<D> {}

impl<D: Digester> fmt::Debug for DigestFunction<D> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "DigestFunction({:?})", self.0)
    }
}

impl<D: Digester> StdHasher for DigestFunction<D> {
    #[inline]
    fn write(&mut self, msg: &[u8]) {
        self.0.input(msg)
    }

    #[inline]
    fn finish(&self) -> u64 {
        unreachable!("unused by Function -- should never be called")
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, PartialOrd, Ord, Default)]
pub struct DigestDomain(pub [u8; 32]);

impl Rand for DigestDomain {
    fn rand<R: Rng>(rng: &mut R) -> Self {
        // generating an Fr and converting it, to ensure we stay in the field
        rng.gen::<Fr>().into()
    }
}

impl AsRef<[u8]> for DigestDomain {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl<D: Digester> Hashable<DigestFunction<D>> for DigestDomain {
    fn hash(&self, state: &mut DigestFunction<D>) {
        state.write(self.as_ref())
    }
}

impl From<Fr> for DigestDomain {
    fn from(val: Fr) -> Self {
        let mut res = Self::default();
        val.into_repr().write_le(&mut res.0[0..32]).unwrap();

        res
    }
}

impl From<DigestDomain> for Fr {
    fn from(val: DigestDomain) -> Self {
        let mut raw = val.0;
        // strip last two bits, to make them stay in Fr
        raw[31] &= 0b0011_1111;

        let mut res = FrRepr::default();
        res.read_le(&raw[0..32]).unwrap();

        Fr::from_repr(res).unwrap()
    }
}

impl Domain for DigestDomain {
    fn serialize(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    fn into_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    fn try_from_bytes(raw: &[u8]) -> Result<Self> {
        if raw.len() != 32 {
            return Err(Error::InvalidInputSize);
        }
        let mut res = DigestDomain::default();
        res.0.copy_from_slice(&raw[0..32]);
        Ok(res)
    }

    fn write_bytes(&self, dest: &mut [u8]) -> Result<()> {
        if dest.len() < 32 {
            return Err(Error::InvalidInputSize);
        }
        dest[0..32].copy_from_slice(&self.0[..]);
        Ok(())
    }
}

impl<D: Digester> HashFunction<DigestDomain> for DigestFunction<D> {
    fn hash(data: &[u8]) -> DigestDomain {
        let hashed = D::digest(data);
        let mut res = DigestDomain::default();
        res.0.copy_from_slice(&hashed[..]);

        res
    }

    // TODO: correct hash circuit
    fn hash_node_circuit<E: JubjubEngine, CS: ConstraintSystem<E>>(
        mut cs: CS,
        left: Vec<Boolean>,
        right: Vec<Boolean>,
        height: usize,
        _params: &E::Params,
    ) -> ::std::result::Result<AllocatedNum<E>, SynthesisError> {
        let mut preimage: Vec<Boolean> = vec![];
        let mut height_bytes = vec![];
        height_bytes
            .write_u64::<LittleEndian>(height as u64)
            .expect("failed to write height");

        preimage.extend(
            multipack::bytes_to_bits_le(&height_bytes)
                .iter()
                .enumerate()
                .map(|(i, b)| {
                    AllocatedBit::alloc(cs.namespace(|| format!("height_bit {}", i)), Some(*b))
                        .map(Boolean::Is)
                })
                .collect::<::std::result::Result<Vec<Boolean>, _>>()?,
        );
        preimage.extend(left);
        while preimage.len() % 8 != 0 {
            preimage.push(Boolean::Constant(false));
        }

        preimage.extend(right);
        while preimage.len() % 8 != 0 {
            preimage.push(Boolean::Constant(false));
        }

        let personalization = vec![0u8; 8];
        let alloc_bits = blake2s_circuit(cs.namespace(|| "hash"), &preimage[..], &personalization)?;

        let bits = alloc_bits
            .iter()
            .map(|v| v.get_value().unwrap())
            .collect::<Vec<bool>>();

        // TODO: figure out if we can avoid this
        let frs = multipack::compute_multipacking::<E>(&bits);

        AllocatedNum::<E>::alloc(cs.namespace(|| "num"), || Ok(frs[0]))
    }
}

impl<D: Digester> Algorithm<DigestDomain> for DigestFunction<D> {
    #[inline]
    fn hash(&mut self) -> DigestDomain {
        let mut h = [0u8; 32];
        h.copy_from_slice(self.0.clone().result().as_ref());
        h.into()
    }

    #[inline]
    fn reset(&mut self) {
        self.0.reset();
    }

    fn leaf(&mut self, leaf: DigestDomain) -> DigestDomain {
        leaf
    }

    fn node(&mut self, left: DigestDomain, right: DigestDomain, height: usize) -> DigestDomain {
        (height as u64).hash(self);

        let mut l = left;
        l.0[31] &= 0b0011_1111;

        let mut r = right;
        r.0[31] &= 0b0011_1111;

        l.hash(self);
        r.hash(self);

        self.hash()
    }
}

impl From<[u8; 32]> for DigestDomain {
    #[inline]
    fn from(val: [u8; 32]) -> Self {
        DigestDomain(val)
    }
}

impl From<DigestDomain> for [u8; 32] {
    #[inline]
    fn from(val: DigestDomain) -> Self {
        val.0
    }
}
