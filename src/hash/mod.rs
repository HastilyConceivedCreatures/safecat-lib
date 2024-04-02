mod poseidon2;

use ark_ff::Field;
use crate::Error;

/// Absorption function ending in a squeeze.
fn absorb_and_squeeze<F: Field>(
    permutation: fn(&[F]) -> Vec<F>,
    state: &mut [F],
    rate: usize,
    rate_before_capacity_ind: bool,
    input: &[F],
) -> Result<(), Error> {
    if rate >= state.len() {
        return Err("The rate must be less than the state size.".into());
    };

    let capacity = state.len() - rate;

    // Figure out state slice bounds
    let rate_start = if rate_before_capacity_ind {
        0
    } else {
        capacity
    };

    // Split input into `rate`-sized chunks
    let input_chunks = input.chunks(rate);

    // Add each chunk to the state and permute
    input_chunks.for_each(|chunk| {
        chunk.into_iter().enumerate().for_each(|(i, m)| {
            state[rate_start + i] += m;
        });
        state.clone_from_slice(&permutation(state));
    });

    Ok(())
}
