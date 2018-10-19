use std::fmt;
use std::hash::Hasher as StdHasher;
use std::marker::PhantomData;

use merkle_light::hash::{Algorithm, Hashable};
use pairing::bls12_381::Fr;
use rand::{Rand, Rng};
use sha2::Digest;

use super::{Domain, HashFunction, Hasher};
use error::*;

pub trait Digester: Digest + Clone + Default + ::std::fmt::Debug {}

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

    fn kdf(_data: &[u8], _m: usize) -> Self::Domain {
        unimplemented!()
    }

    fn sloth_encode(
        _key: &Self::Domain,
        _ciphertext: &Self::Domain,
        _rounds: usize,
    ) -> Self::Domain {
        unimplemented!()
    }

    fn sloth_decode(
        _key: &Self::Domain,
        _ciphertext: &Self::Domain,
        _rounds: usize,
    ) -> Self::Domain {
        unimplemented!()
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
        DigestDomain(rng.gen())
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
    fn from(_val: Fr) -> Self {
        unimplemented!()
    }
}
impl From<DigestDomain> for Fr {
    fn from(_val: DigestDomain) -> Self {
        unimplemented!()
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
        height.hash(self);

        left.hash(self);
        right.hash(self);
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