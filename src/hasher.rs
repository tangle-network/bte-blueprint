// Code taken from https://github.com/shekohex/orehub/blob/master/npvdkgrs/src/hash.rs

use ark_bls12_381::Fr;
use ark_bls12_381::{Fq, G1Affine, G1Projective as G1, G2Affine, G2Projective as G2};
use ark_ec::hashing::{
    curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve,
    HashToCurveError,
};
use ark_ff::field_hashers::DefaultFieldHasher;
use ark_ff::BigInteger;
use ark_ff::PrimeField;
use sha3::{digest::FixedOutput, Digest, Keccak256, Keccak384};

/// Hash to field hasher
type H2F = DefaultFieldHasher<Keccak256>;
type G1M2C = WBMap<ark_bls12_381::g1::Config>;
type G2M2C = WBMap<ark_bls12_381::g2::Config>;

/// Hash to curve hasher in G1
type G1Hasher = MapToCurveBasedHasher<G1, H2F, G1M2C>;
/// Hash to curve hasher in G2
type G2Hasher = MapToCurveBasedHasher<G2, H2F, G2M2C>;

/// Domain separation tags for hash functions for G1.
const G1_DST: &[u8] = b"npvdkgrs-bls12-381-g1-hash-to-curve";
/// Domain separation tags for hash functions for G2.
const G2_DST: &[u8] = b"npvdkgrs-bls12-381-g2-hash-to-curve";

/// Produce a hash of the message, which also depends on the domain.
/// The output of the hash is a curve point in [`G1`]
pub fn hash_to_g1(message: &[u8]) -> Result<G1Affine, HashToCurveError> {
    let hasher = G1Hasher::new(G1_DST)?;
    hasher.hash(message)
}

/// Produce a hash of the message, which also depends on the domain.
/// The output of the hash is a curve point in [`G2`]
pub fn hash_to_g2(msg: &[u8]) -> Result<G2Affine, HashToCurveError> {
    let hasher = G2Hasher::new(G2_DST)?;
    hasher.hash(msg)
}

/// Produce a hash of the message, which also depends on the domain.
/// The output of the hash is a scalar field element.
pub fn hash_to_fp(msg: &[u8]) -> Fq {
    let mut hasher = Keccak384::new();
    hasher.update(msg);
    let hash = hasher.finalize_fixed();
    Fq::from_le_bytes_mod_order(&hash)
}

/// Produce a hash of the message, which also depends on the domain.
/// The output of the hash is a scalar field element.
pub fn hash_to_fr(msg: &[u8]) -> Fr {
    let mut hasher = Keccak256::new();
    hasher.update(msg);
    let hash = hasher.finalize_fixed();
    Fr::from_le_bytes_mod_order(&hash)
}

/// Produce a hash of the [Fq] Scalar field element.
pub fn hash_fq_to_32(f: Fq) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    let bytes = f.into_bigint().to_bytes_le();
    hasher.update(&bytes);
    let hash = hasher.finalize_fixed();
    hash.into()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn h2g1() {
        let msg = b"hello world";
        let g1 = hash_to_g1(msg).unwrap();
        assert!(bool::from(g1.is_on_curve()));

        let msg = b"000fa0fdaffdaaeeeee0012342aaaaaaaaaa098756224235635242342325";
        let g1 = hash_to_g1(msg).unwrap();
        assert!(bool::from(g1.is_on_curve()));
    }

    #[test]
    fn h2g2() {
        let msg = b"hello world";
        let g2 = hash_to_g2(msg).unwrap();
        assert!(bool::from(g2.is_on_curve()));

        let msg = b"000fa0fdaffdaaeeeee0012342aaaaaaaaaa098756224235635242342325";
        let g2 = hash_to_g2(msg).unwrap();
        assert!(bool::from(g2.is_on_curve()));
    }

    #[test]
    fn h2fq() {
        let msg = b"hello world";
        let _scalar = hash_to_fp(msg); // no error, a scalar was successfully created
        let msg = b"another test and three pugs";
        let _scalar = hash_to_fp(msg); // no error, a scalar was successfully created
        let msg = b"000fa0fdaffdaaeeeee0012342aaaaaaaaaa098756224235635242342325";
        let _scalar = hash_to_fp(msg); // no error, a scalar was successfully created
    }
}
