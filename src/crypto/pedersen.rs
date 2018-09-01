use byteorder::{ByteOrder, LittleEndian};
use pairing::bls12_381::{Bls12, Fr, FrRepr};
use pairing::PrimeFieldRepr;
use sapling_crypto::jubjub::JubjubBls12;
use sapling_crypto::pedersen_hash::{pedersen_hash, Personalization};

use fr32::bytes_into_frs;
use util::{bits_to_bytes, bytes_into_bits};

use bit_vec::BitVec;

lazy_static! {
    pub static ref JJ_PARAMS: JubjubBls12 = JubjubBls12::new();
}

pub const PEDERSEN_BLOCK_SIZE: usize = 256;
pub const PEDERSEN_BLOCK_BYTES: usize = PEDERSEN_BLOCK_SIZE / 8;

/// Pedersen hashing for inputs that have length mulitple of the block size `256`. Based on pedersen hashes and a Merkle-Damgard construction.
pub fn pedersen_md_no_padding(data: &[u8]) -> Fr {
    assert!(
        data.len() >= 2 * PEDERSEN_BLOCK_BYTES,
        "must be at least 2 block sizes long, got {}bits",
        data.len()
    );
    assert_eq!(
        data.len() % PEDERSEN_BLOCK_BYTES,
        0,
        "input must be a multiple of the blocksize"
    );
    let mut chunks = data.chunks(PEDERSEN_BLOCK_BYTES);
    let mut cur: Vec<u8> = vec![0; 2 * PEDERSEN_BLOCK_BYTES];
    cur[0..PEDERSEN_BLOCK_BYTES].copy_from_slice(chunks.nth(0).unwrap());

    for block in chunks {
        cur[PEDERSEN_BLOCK_BYTES..].copy_from_slice(block);
        let mut res = Vec::<u8>::with_capacity(32);
        pedersen_compression(&cur, &mut res);
        cur[0..PEDERSEN_BLOCK_BYTES].copy_from_slice(&res);
    }

    let frs = bytes_into_frs::<Bls12>(&cur[0..PEDERSEN_BLOCK_BYTES])
        .expect("pedersen must generate valid fr elements");
    assert_eq!(frs.len(), 1);
    frs[0]
}

pub fn pedersen_compression(bytes: &[u8], out: &mut Vec<u8>) {
    //    let reversed_bytes = bytes.iter().rev().map(|x| *x).collect::<Vec<u8>>();
    let reversed_bytes = bytes.iter().rev().cloned().collect::<Vec<u8>>();
    let bit_iterator = BitVec::from_bytes(&reversed_bytes);
    let reversed = bit_iterator.iter().rev();

    let (x, _) =
        pedersen_hash::<Bls12, _>(Personalization::NoteCommitment, reversed, &JJ_PARAMS).into_xy();
    let x: FrRepr = x.into();
    x.write_le(out).expect("failed to write result hash");
}

pub fn pedersen_md_no_padding_z(data: &[u8]) -> Fr {
    let data_bits = bytes_into_bits(data);

    assert!(
        data_bits.len() >= 2 * PEDERSEN_BLOCK_SIZE,
        "must be at least 2 block sizes long, got {}bits",
        data_bits.len()
    );
    assert_eq!(
        data_bits.len() % PEDERSEN_BLOCK_SIZE,
        0,
        "input must be a multiple of the blocksize"
    );
    let mut chunks = data_bits.chunks(PEDERSEN_BLOCK_SIZE);
    let mut cur: Vec<bool> = vec![false; 2 * PEDERSEN_BLOCK_SIZE];
    cur[0..PEDERSEN_BLOCK_SIZE].copy_from_slice(chunks.nth(0).unwrap());

    for block in chunks {
        cur[PEDERSEN_BLOCK_SIZE..].copy_from_slice(block);
        pedersen_compression_z(&mut cur, 2 * PEDERSEN_BLOCK_SIZE);
    }

    let frs = bytes_into_frs::<Bls12>(&bits_to_bytes(&cur[0..PEDERSEN_BLOCK_SIZE]))
        .expect("pedersen must generate valid fr elements");
    assert_eq!(frs.len(), 1);
    frs[0]
}

/// bits, is the input values, which get overwritten with the result.
pub fn pedersen_compression_z(bits: &mut [bool], data_len: usize) {
    assert!(bits.len() >= PEDERSEN_BLOCK_SIZE, "bits to small");

    let x: FrRepr = pedersen_hash::<Bls12, _>(
        Personalization::NoteCommitment,
        bits.iter().take(data_len).cloned(),
        &JJ_PARAMS,
    ).into_xy()
    .0
    .into();

    // write result into target vec
    let mut scratch = vec![0u8; 8];
    for (i, digit) in x.as_ref().iter().enumerate() {
        LittleEndian::write_u64(&mut scratch, *digit);

        for k in 0..8 {
            for j in 0..8 {
                bits[i * 64 + k * 8 + j] = (scratch[k] >> j) & 1u8 == 1u8
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::Fr;
    use pairing::Field;
    use rand::{Rng, SeedableRng, XorShiftRng};

    #[test]
    fn test_bit_vec_le() {
        let bytes = b"ABC";
        let bits = bytes_into_bits(bytes);

        let reversed_bytes = bytes.iter().rev().map(|x| *x).collect::<Vec<u8>>();
        let bit_iterator = BitVec::from_bytes(&reversed_bytes);
        let reversed = bit_iterator.iter().rev();
        let bits2 = reversed.collect::<Vec<bool>>();

        assert_eq!(bits, bits2);
    }

    #[test]
    fn test_pedersen_compression() {
        let bytes = b"some bytes";
        let mut hashed = Vec::with_capacity(32);
        pedersen_compression(bytes, &mut hashed);
        let expected = vec![
            213, 235, 66, 156, 7, 85, 177, 39, 249, 31, 160, 247, 29, 106, 36, 46, 225, 71, 116,
            23, 1, 89, 82, 149, 45, 189, 27, 189, 144, 98, 23, 98,
        ];
        assert_eq!(expected, hashed);
    }

    #[test]
    fn test_pedersen_md_no_padding() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        for i in 2..5 {
            let x: Vec<u8> = (0..i * 32).map(|_| rng.gen()).collect();
            let hashed_z = pedersen_md_no_padding_z(x.as_slice());
            let hashed = pedersen_md_no_padding(x.as_slice());
            assert_eq!(hashed, hashed_z);
            assert_ne!(hashed, Fr::zero());
        }
    }
}
