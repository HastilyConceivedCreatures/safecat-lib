mod consts;

use ark_ff::Field;
use consts::POSEIDON_4_PARAMS;
use std::str::FromStr;
use zkhash::fields::utils::from_hex;
use zkhash::poseidon2::poseidon2::Poseidon2;

type BN254Scalar = zkhash::fields::bn256::FpBN256;

/// Poseidon2 permutation on 4 BN254 elements with alpha = 5
/// and appropriate parameters. Returns a vector of  BN254 field
/// elements.
///
/// # Arguments
/// * `input` - A slice of BN254 field elements.
pub fn poseidon2_bn254_x5_4(input: &[BN254Scalar]) -> Vec<BN254Scalar> {
    Poseidon2::new(&POSEIDON_4_PARAMS).permutation(input)
}

/// Noir-compatible Poseidon2 sponge using `poseidon2_bn254_x5_4`.
/// Returns a BN254 field element.
///
/// # Arguments
/// * `input` - A slice of BN254 field elements to be hashed.
/// * 'variable_size` - An indicator of whether the slice to be hashed is a slice of
///    a larger array or vector. Included for technical reasons to match the Noir
///    implementation where variable-length arrays cannot be passed into programs.
pub fn poseidon2_bn254_sponge(input: &[BN254Scalar], variable_size: bool) -> BN254Scalar {
    // Initialise state
    let mut state = vec![BN254Scalar::ZERO; 4];

    // Add length information to capacity
    state[3] = *consts::POW_TWO_64 * BN254Scalar::from_str(input.len().to_string().as_str()).unwrap();

    // Copy input slice and append 1 in case the input has 'variable size'; this is the case when
    // only the first N elements of an input array of length M > N are hashed in Noir, i.e. the
    // call noir_poseidon2_sponge(input, true) in Rust is equivalent to the call
    // Poseidon2::hash(input1, N) for an array input1 of size M > N such that input[i] = input1[i]
    // for i < N.
    let mut input_vec = input.to_vec();
    if variable_size {
        let _ = &input_vec.push(BN254Scalar::ONE);
    }
    let input = &input_vec;

    // Absorb and squeeze once
    super::absorb_and_squeeze(poseidon2_bn254_x5_4, &mut state, 3, true, input).unwrap();

    // Output the first element of the rate part
    state[0]
}

/// Poseidon2 sponge tests
#[test]
fn test_poseidon2_sponge() {
    let map_array = |a: &[&str]| a.into_iter().map(|s| from_hex(s)).collect::<Vec<BN254Scalar>>();

    let test0 = map_array(&["0x01", "0x02"]);

    assert_eq!(
        poseidon2_bn254_sponge(&test0, false),
        from_hex("0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383")
    );
    assert_eq!(
        poseidon2_bn254_sponge(&test0, true),
        from_hex("0x05183cc69f95f56ec1bbd9eedd6f337448abba8ed4bc19799ae2c684fea26dfe")
    );

    let test1 = map_array(&["0x01", "0x02", "0x03"]);

    assert_eq!(
        poseidon2_bn254_sponge(&test1, false),
        from_hex("0x23864adb160dddf590f1d3303683ebcb914f828e2635f6e85a32f0a1aecd3dd8")
    );
    assert_eq!(
        poseidon2_bn254_sponge(&test1, true),
        from_hex("0x2d49db04e5c4f35294624667bdbd2914c6bd4b0631a7564719ab7b1ff55dd516")
    );

    let test2 = map_array(&["0x01", "0x02", "0x03", "0x04", "0x05"]);

    assert_eq!(
        poseidon2_bn254_sponge(&test2, false),
        from_hex("0x2247be7014a54d17342a7ef677f58d28877780d203860396967f5d0a18d259db")
    );
    assert_eq!(
        poseidon2_bn254_sponge(&test2, true),
        from_hex("0x137329d62bbee07bad793a36d53b43bb642c8933ac7fef10e0905fdb89487f9f")
    );
}
