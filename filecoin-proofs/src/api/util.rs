use anyhow::{Context, Result};
use paired::bls12_381::Bls12;
use paired::Engine;
use storage_proofs::fr32::{bytes_into_fr, fr_into_bytes};
use storage_proofs::hasher::Domain;

use crate::types::Commitment;

pub(crate) fn as_safe_commitment<H: Domain, T: AsRef<str>>(
    comm: &Commitment,
    commitment_name: T,
) -> Result<H> {
    bytes_into_fr::<Bls12>(comm)
        .map(Into::into)
        .with_context(|| format!("Invalid commitment ({})", commitment_name.as_ref(),))
}

pub(crate) fn commitment_from_fr<E: Engine>(fr: E::Fr) -> Commitment {
    let mut commitment = [0; 32];
    for (i, b) in fr_into_bytes::<E>(&fr).iter().enumerate() {
        commitment[i] = *b;
    }
    commitment
}

/// QAP cache for PoRep && PoSt circuit
use lazy_static::lazy_static;
use bellperson::groth16::{Qap, import_qap};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

type Bls12Qap = Qap<Bls12>;
type Cache<G> = HashMap<String, Arc<G>>;
type QapMemCache = Cache<Bls12Qap>;

lazy_static! {
    static ref QAP_MEM_CACHE: Mutex<QapMemCache> = Default::default();
}

pub fn qap_cache_lookup<F, G>(
    cache_ref: &Mutex<Cache<G>>,
    id: String,
    loader: F,
) -> Result<Arc<G>>
    where
        F: FnOnce() -> Result<G>,
        G: Send + Sync,
{
    println!("trying qap memory cache for: {}", &id);
    {
        let cache = (*cache_ref).lock().unwrap();

        if let Some(entry) = cache.get(&id) {
            println!("found qap in memory cache for {}", &id);
            return Ok(entry.clone());
        }
    }

    println!("no params in memory cache for {}", &id);
    let new_entry = Arc::new(loader()?);
    let res = new_entry.clone();
    {
        let cache = &mut (*cache_ref).lock().unwrap();
        cache.insert(id, new_entry);
    }

    Ok(res)
}

pub fn get_qap(circuit_name: &str, qap_file_path: &str) -> anyhow::Result<Arc<Bls12Qap>> {
    let loader = || {
        import_qap(&qap_file_path).map_err(|err| anyhow::anyhow!(err))
    };
    qap_cache_lookup(&*QAP_MEM_CACHE, String::from(circuit_name), loader)
}
