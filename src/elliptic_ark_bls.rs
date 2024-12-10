use ark_ec::AffineRepr;

pub fn convert_bls_to_ark_bls_g1(g: &bls12_381_plus::G1Projective) -> ark_bls12_381::G1Projective {
    let g_affine: bls12_381_plus::G1Affine = g.into();

    let g_affine_ptr = &g_affine as *const bls12_381_plus::G1Affine;

    let x: [u64; 6] = unsafe { *(g_affine_ptr as *const [u64; 6]) };
    let y: [u64; 6] = unsafe {
        *((g_affine_ptr as *const u8).add(ark_std::mem::size_of::<[u64; 6]>()) as *const [u64; 6])
    };
    let infinity: bool = unsafe {
        *((g_affine_ptr as *const u8).add(2 * ark_std::mem::size_of::<[u64; 6]>()) as *const bool)
    };

    if infinity {
        return ark_bls12_381::G1Affine::zero().into_group();
    } else {
        let fp_x = bls12_381_plus::fp::Fp::from_raw_unchecked(x);
        let fp_y = bls12_381_plus::fp::Fp::from_raw_unchecked(y);

        let fp_x_bytes = fp_x.to_bytes();
        let fp_y_bytes = fp_y.to_bytes();

        let bigint_fp_x = num_bigint::BigUint::from_bytes_be(&fp_x_bytes);
        let bigint_fp_y = num_bigint::BigUint::from_bytes_be(&fp_y_bytes);

        let fq_x = ark_bls12_381::Fq::from(bigint_fp_x);
        let fq_y = ark_bls12_381::Fq::from(bigint_fp_y);

        ark_ec::short_weierstrass::Affine::<ark_bls12_381::g1::Config>::new(fq_x, fq_y).into_group()
    }
}

pub fn convert_bls_to_ark_bls_fr(s: &bls12_381_plus::Scalar) -> ark_bls12_381::Fr {
    ark_bls12_381::Fr::from(num_bigint::BigUint::from_bytes_be(&s.to_be_bytes()))
}

// #[cfg(test)]
// mod tests {
//     use super::*;
// use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};

//     fn secret_share<F: ark_ff::FftField>(n: usize, t: usize) -> (Vec<F>, Vec<F>) {
//         let mut sk_shares = vec![F::zero(); n];
//         let rng = &mut ark_std::rand::thread_rng();
//         let sk = F::rand(rng);

//         sk_shares[0] = sk;
//         for i in 1..t {
//             sk_shares[i] = F::rand(rng);
//         }

//         let share_domain = Radix2EvaluationDomain::<F>::new(n).unwrap();
//         share_domain.fft_in_place(&mut sk_shares);

//         let lagrange_coeffs_0 = share_domain.evaluate_all_lagrange_coefficients(F::zero());

//         // compute inner product of lagrange coeffs and sk_shares and check that it matches sk
//         let sk_from_shares: F = lagrange_coeffs_0
//             .iter()
//             .zip(sk_shares.clone().iter())
//             .map(|(a, b)| *a * *b)
//             .sum();

//         assert_eq!(sk, sk_from_shares);

//         (sk_shares, lagrange_coeffs_0)
//     }

//     #[test]
//     fn test_generator_conversion() {
//         let g = <bls12_381_plus::G1Projective as group::Group>::generator();
//         let ark_g = <ark_bls12_381::G1Projective as ark_ec::Group>::generator();
//         let recovered_ark_g = convert_bls_to_ark_bls_g1(&g);
//         assert_eq!(recovered_ark_g, ark_g);
//     }

//     #[test]
//     fn test_scalar_multiplication() {
//         let g = <bls12_381_plus::G1Projective as group::Group>::generator();
//         let ark_g = <ark_bls12_381::G1Projective as ark_ec::Group>::generator();

//         let r = <bls12_381_plus::Scalar as ff::Field>::random(&mut rand::thread_rng());
//         let gr = r * g;

//         let ark_r = ark_bls12_381::Fr::from(num_bigint::BigUint::from_bytes_be(&r.to_be_bytes()));
//         let ark_gr = ark_g * ark_r;

//         let recovered_ark_gr = convert_bls_to_ark_bls_g1(&gr);
//         assert_eq!(recovered_ark_gr, ark_gr);
//     }

//     #[test]
//     fn test_secret_sharing() {
//         let g = <bls12_381_plus::G1Projective as group::Group>::generator();
//         let ark_g = <ark_bls12_381::G1Projective as ark_ec::Group>::generator();

//         let (sk_shares, lagrange_coeffs_0) = secret_share::<bls12_381_plus::Scalar>(8, 3);
//         let sk: bls12_381_plus::Scalar = lagrange_coeffs_0
//             .iter()
//             .zip(sk_shares.clone().iter())
//             .map(|(a, b)| *a * *b)
//             .sum();

//         let pk = g * sk;

//         let ark_sk_shares = sk_shares
//             .iter()
//             .map(|s| convert_bls_to_ark_bls_fr(s))
//             .collect::<Vec<_>>();

//         let ark_lagrange_coeffs_0 = lagrange_coeffs_0
//             .iter()
//             .map(|s| convert_bls_to_ark_bls_fr(s))
//             .collect::<Vec<_>>();

//         let ark_sk: ark_bls12_381::Fr = ark_lagrange_coeffs_0
//             .iter()
//             .zip(ark_sk_shares.iter())
//             .map(|(a, b)| *a * *b)
//             .sum();

//         let ark_pk = ark_g * ark_sk;

//         let recovered_ark_pk = convert_bls_to_ark_bls_g1(&pk);
//         assert_eq!(recovered_ark_pk, ark_pk);
//     }
// }
