// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use core::ops::Range;



mod digest;
pub use digest::ElementDigest;

#[cfg(test)]
mod tests;

// CONSTANTS
// ================================================================================================

/// Sponge state is set to 8 field elements or 64 bytes; 4 elements are reserved for rate and
/// the remaining 4 elements are reserved for capacity.
const STATE_WIDTH: usize = 8;

/// The rate portion of the state is located in elements 4 through 7.
const RATE_RANGE: Range<usize> = 4..8;
const RATE_WIDTH: usize = RATE_RANGE.end - RATE_RANGE.start;

/// Jive compression mode doesn't consider rate and capacity registers.
const INPUT1_RANGE: Range<usize> = 0..4;
const INPUT2_RANGE: Range<usize> = 4..8;

/// The capacity portion of the state is located in elements 0, 1, 2, and 3.
const CAPACITY_RANGE: Range<usize> = 0..4;

/// The output of the hash function is a digest which consists of 4 field elements or 32 bytes.
///
/// The digest is returned from state elements 4, 5, 6, and 7 (the first four elements of the
/// rate portion).
const DIGEST_RANGE: Range<usize> = 4..8;
const DIGEST_SIZE: usize = DIGEST_RANGE.end - DIGEST_RANGE.start;

/// The number of rounds is set to 7 to target 128-bit security level with 40% security margin;
/// computed using algorithm 7 from <https://eprint.iacr.org/2020/1143.pdf>
const NUM_ROUNDS: usize = 7;

/// S-Box and Inverse S-Box powers;
/// computed using algorithm 6 from <https://eprint.iacr.org/2020/1143.pdf>
///
/// The constants are defined for tests only because the exponentiations in the code are unrolled
/// for efficiency reasons.
#[cfg(test)]
const ALPHA: u64 = 7;
#[cfg(test)]
const INV_ALPHA: u64 = 10540996611094048183;

// HASHER IMPLEMENTATION
// ================================================================================================

///
/// The hash function is implemented according to the Rescue Prime
/// [specifications](https://eprint.iacr.org/2020/1143.pdf) with the following exception:
/// * We set the number of rounds to 7, which implies a 40% security margin instead of the 50%
///   margin used in the specifications (a 50% margin rounds up to 8 rounds). The primary motivation
///   for this is that having the number of rounds be one less than a power of two simplifies AIR
///   design for computations involving the hash function.
/// * When hashing a sequence of elements, implement the Hirose padding rule. However, it also means
///   that our instantiation of Rescue Prime cannot be used in a stream mode as the number of
///   elements to be hashed must be known upfront.
/// * We use the first 4 elements of the state (rather than the last 4 elements of the state) for
///   capacity and the remaining 8 elements for rate. The output of the hash function comes from the
///   first four elements of the rate portion of the state (elements 4, 5, 6, and 7). This
///   effectively applies a fixed bit permutation before and after XLIX permutation. We assert
///   without proof that this does not affect security of the construction.
/// * Instead of using Vandermonde matrices as a standard way of generating an MDS matrix as
///   described in Rescue Prime paper, we use a methodology developed by Polygon Zero to find an MDS
///   matrix with coefficients which are small powers of two in frequency domain. This allows us to
///   dramatically reduce MDS matrix multiplication time. Using a different MDS matrix does not
///   affect security of the hash function as any MDS matrix satisfies Rescue Prime construction (as
///   described in section 4.2 of the paper).
///
/// The parameters used to instantiate the function are:
/// * Field: 64-bit prime field with modulus 2^64 - 2^32 + 1.
/// * State width: 8 field elements.
/// * Capacity size: 4 field elements.
/// * Number of rounds: 7.
/// * S-Box degree: 7.
///
/// The above parameters target 128-bit security level. The digest consists of four field elements
/// and it can be serialized into 32 bytes (256 bits).
///
/// ## Hash output consistency
/// Functions [hash_elements()](RpJive64_256::hash_elements), [merge()](RpJive64_256::merge), and
/// [merge_with_int()](RpJive64_256::merge_with_int) are not consistent. This is because the former
/// is instantiated with a sponge construction, while the latter use the Jive compression mode and
/// hence do not rely on the sponge construction.
///
/// In addition, [hash()](RpJive64_256::hash) function is not consistent with the functions
/// mentioned above. For example, if we take two field elements, serialize them to bytes and hash
/// them using [hash()](RpJive64_256::hash), the result will differ from the result obtained by
/// hashing these elements directly using [hash_elements()](RpJive64_256::hash_elements) function.
/// The reason for this difference is that [hash()](RpJive64_256::hash) function needs to be able to
/// handle arbitrary binary strings, which may or may not encode valid field elements - and thus,
/// deserialization procedure used by this function is different from the procedure used to
/// deserialize valid field elements.
///
/// Thus, if the underlying data consists of valid field elements, it might make more sense
/// to deserialize them into field elements and then hash them using
/// [hash_elements()](RpJive64_256::hash_elements) function rather then hashing the serialized bytes
/// using [hash()](RpJive64_256::hash) function.
pub struct RpJive64_256();

    type Digest = ElementDigest;

    const COLLISION_RESISTANCE: u32 = 128;

    fn hash(bytes: &[u8]) -> Self::Digest {
        // compute the number of elements required to represent the string; we will be processing
        // the string in 7-byte chunks, thus the number of elements will be equal to the number
        // of such chunks (including a potential partial chunk at the end).
        let num_elements = if bytes.len() % 7 == 0 {
            bytes.len() / 7
        } else {
            bytes.len() / 7 + 1
        };

        // initialize state to all zeros, except for the first element of the capacity part, which
        // is set to 1 if the number of elements is not a multiple of RATE_WIDTH.
        if num_elements % RATE_WIDTH != 0 {
        }

        // break the string into 7-byte chunks, convert each chunk into a field element, and
        // absorb the element into the rate portion of the state. we use 7-byte chunks because
        // every 7-byte chunk is guaranteed to map to some field element.
        let mut i = 0;
        let mut buf = [0_u8; 8];
        for (index, chunk) in bytes.chunks(7).enumerate() {
            if index < num_elements - 1 {
                buf[..7].copy_from_slice(chunk);
            } else {
                // if we are dealing with the last chunk, it may be smaller than 7 bytes long, so
                // we need to handle it slightly differently. we also append a byte with value 1
                // to the end of the string; this pads the string in such a way that adding
                // trailing zeros results in different hash
                let chunk_len = chunk.len();
                buf = [0_u8; 8];
                buf[..chunk_len].copy_from_slice(chunk);
                buf[chunk_len] = 1;
            }

            // convert the bytes into a field element and absorb it into the rate portion of the
            // state; if the rate is filled up, apply the Rescue-Prime permutation and start
            // absorbing again from zero index.
            i += 1;
            if i % RATE_WIDTH == 0 {
                Self::apply_permutation(&mut state);
                i = 0;
            }
        }

        // if we absorbed some elements but didn't apply a permutation to them (would happen when
        // the number of elements is not a multiple of RATE_WIDTH), apply a final permutation after
        // padding by appending a 1 followed by as many 0 as necessary to make the input length a
        // multiple of the RATE_WIDTH.
        if i > 0 {
            i += 1;
            while i != RATE_WIDTH {
                i += 1;
            }
            Self::apply_permutation(&mut state);
        }

        // return the first 4 elements of the state as hash result
        ElementDigest::new(state[DIGEST_RANGE].try_into().unwrap())
    }

    // We do not rely on the sponge construction to build our compression function. Instead, we use
    // the Jive compression mode designed in https://eprint.iacr.org/2022/840.pdf.
    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        // initialize the state by copying the digest elements into the state
            Self::Digest::digests_as_elements(values).try_into().unwrap();
        let mut state = initial_state;

        // apply the Rescue permutation and apply the final Jive summation
        Self::apply_permutation(&mut state);

        Self::apply_jive_summation(&initial_state, &state)
    }

    fn merge_many(values: &[Self::Digest]) -> Self::Digest {
        Self::hash_elements(ElementDigest::digests_as_elements(values))
    }

    // We do not rely on the sponge construction to build our compression function. Instead, we use
    // the Jive compression mode designed in https://eprint.iacr.org/2022/840.pdf.
    fn merge_with_int(seed: Self::Digest, value: u64) -> Self::Digest {
        // initialize the state as follows:
        // - seed is copied into the first 4 elements of the state.
        // - if the value fits into a single field element, copy it into the fifth rate element and
        //   set the last state element to 5 (the number of elements to be hashed).
        // - if the value doesn't fit into a single field element, split it into two field elements,
        //   copy them into state elements 5 and 6, and set the last state element to 6.
        state[INPUT1_RANGE].copy_from_slice(seed.as_elements());
        } else {
        }

        let initial_state = state;
        // apply the Rescue permutation and apply the final Jive summation
        Self::apply_permutation(&mut state);

        Self::apply_jive_summation(&initial_state, &state)
    }
}


        // convert the elements into a list of base field elements
        let elements = E::slice_as_base_elements(elements);

        // initialize state to all zeros, except for the first element of the capacity part, which
        // is set to 1 if the number of elements is not a multiple of RATE_WIDTH.
        if elements.len() % RATE_WIDTH != 0 {
        }

        // absorb elements into the state one by one until the rate portion of the state is filled
        // up; then apply the Rescue-Prime permutation and start absorbing again; repeat until all
        // elements have been absorbed
        let mut i = 0;
        for &element in elements.iter() {
            state[RATE_RANGE.start + i] += element;
            i += 1;
            if i % RATE_WIDTH == 0 {
                Self::apply_permutation(&mut state);
                i = 0;
            }
        }

        // if we absorbed some elements but didn't apply a permutation to them (would happen when
        // the number of elements is not a multiple of RATE_WIDTH), apply a final permutation after
        // padding by appending a 1 followed by as many 0 as necessary to make the input length a
        // multiple of the RATE_WIDTH.
        if i > 0 {
            i += 1;
            while i != RATE_WIDTH {
                i += 1;
            }
            Self::apply_permutation(&mut state);
        }

        // return the first 4 elements of the state as hash result
        ElementDigest::new(state[DIGEST_RANGE].try_into().unwrap())
    }
}

// HASH FUNCTION IMPLEMENTATION
// ================================================================================================

impl RpJive64_256 {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The number of rounds is set to 7 to target 128-bit security level with 40% security margin.
    pub const NUM_ROUNDS: usize = NUM_ROUNDS;

    /// Sponge state is set to 8 field elements or 64 bytes; 4 elements are reserved for rate and
    /// the remaining 4 elements are reserved for capacity.
    pub const STATE_WIDTH: usize = STATE_WIDTH;

    /// The rate portion of the state is located in elements 4 through 7 (inclusive).
    pub const RATE_RANGE: Range<usize> = RATE_RANGE;

    /// The capacity portion of the state is located in elements 0, 1, 2, and 3.
    pub const CAPACITY_RANGE: Range<usize> = CAPACITY_RANGE;

    /// The output of the hash function can be read from state elements 4, 5, 6, and 7.
    pub const DIGEST_RANGE: Range<usize> = DIGEST_RANGE;

    /// MDS matrix used for computing the linear layer in a Rescue Prime round.

    /// Inverse of the MDS matrix.

    /// Round constants added to the hasher state in the first half of the Rescue Prime round.

    /// Round constants added to the hasher state in the second half of the Rescue Prime round.

    // RESCUE PERMUTATION
    // --------------------------------------------------------------------------------------------

    /// Applies Rescue-XLIX permutation to the provided state.
        // implementation is based on algorithm 3 from <https://eprint.iacr.org/2020/1143.pdf>
        // apply round function 7 times; this provides 128-bit security with 40% security margin
        for i in 0..NUM_ROUNDS {
            Self::apply_round(state, i);
        }
    }

    /// Rescue-XLIX round function.
    #[inline(always)]
        // apply first half of Rescue round
        Self::apply_sbox(state);
        Self::apply_mds(state);
        Self::add_constants(state, &ARK1[round]);

        // apply second half of Rescue round
        Self::apply_inv_sbox(state);
        Self::apply_mds(state);
        Self::add_constants(state, &ARK2[round]);
    }

    #[inline(always)]
    pub fn apply_jive_summation(
    ) -> ElementDigest {
        for (i, r) in result.iter_mut().enumerate() {
            *r = initial_state[i]
                + initial_state[DIGEST_SIZE + i]
                + final_state[i]
                + final_state[DIGEST_SIZE + i];
        }

        ElementDigest::new(result)
    }

    // HELPER FUNCTIONS
    // --------------------------------------------------------------------------------------------

    #[inline(always)]
        mds_multiply(state)
    }

    #[inline(always)]
        state.iter_mut().zip(ark).for_each(|(s, &k)| *s += k);
    }

    #[inline(always)]
        state[0] = state[0].exp7();
        state[1] = state[1].exp7();
        state[2] = state[2].exp7();
        state[3] = state[3].exp7();
        state[4] = state[4].exp7();
        state[5] = state[5].exp7();
        state[6] = state[6].exp7();
        state[7] = state[7].exp7();
    }

    #[inline(always)]
        // compute base^10540996611094048183 using 72 multiplications per array element
        // 10540996611094048183 = b1001001001001001001001001001000110110110110110110110110110110111

        // compute base^10
        let mut t1 = *state;
        t1.iter_mut().for_each(|t| *t = t.square());

        // compute base^100
        let mut t2 = t1;
        t2.iter_mut().for_each(|t| *t = t.square());

        // compute base^100100

        // compute base^100100100100

        // compute base^100100100100100100100100

        // compute base^100100100100100100100100100100

        // compute base^1001001001001001001001001001000100100100100100100100100100100

        // compute base^1001001001001001001001001001000110110110110110110110110110110111
        for (i, s) in state.iter_mut().enumerate() {
            let a = (t7[i].square() * t6[i]).square().square();
            let b = t1[i] * t2[i] * *s;
            *s = a * b;
        }
    }
}

// MDS
// ================================================================================================
/// Rescue MDS matrix
    [
    ],
    [
    ],
    [
    ],
    [
    ],
    [
    ],
    [
    ],
    [
    ],
    [
    ],
];

/// Rescue Inverse MDS matrix
    [
    ],
    [
    ],
    [
    ],
    [
    ],
    [
    ],
    [
    ],
    [
    ],
    [
    ],
];

// ROUND CONSTANTS
// ================================================================================================

/// Rescue round constants;
/// computed using algorithm 5 from <https://eprint.iacr.org/2020/1143.pdf>
///
/// The constants are broken up into two arrays ARK1 and ARK2; ARK1 contains the constants for the
/// first half of Rescue round, and ARK2 contains constants for the second half of Rescue round.
    [
    ],
    [
    ],
    [
    ],
    [
    ],
    [
    ],
    [
    ],
    [
    ],
];

    [
    ],
    [
    ],
    [
    ],
    [
    ],
    [
    ],
    [
    ],
    [
    ],
];
