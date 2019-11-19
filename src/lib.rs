use bitvec::{self, BitVec};
use ff::{PrimeField, PrimeFieldRepr};
use fil_sapling_crypto::jubjub::JubjubBls12;
use fil_sapling_crypto::pedersen_hash::{pedersen_hash as sapling_pedersen_hash, Personalization};
use paired::bls12_381::Bls12;

pub fn pedersen_hash(preimage: &[u8]) -> [u8; 32] {
    let params = JubjubBls12::new();

    let preimage_bits = BitVec::<bitvec::LittleEndian, u8>::from(preimage);
    let preimage_bit_len = 8 * preimage.len();

    let digest_fr = sapling_pedersen_hash::<Bls12, _>(
        Personalization::None,
        preimage_bits.iter().take(preimage_bit_len),
        &params,
    )
    .into_xy()
    .0;

    let mut digest_bytes = [0u8; 32];
    digest_fr.into_repr().write_le(&mut digest_bytes[..32]).unwrap();
    digest_bytes
}
