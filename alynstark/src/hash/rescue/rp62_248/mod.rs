// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.



mod digest;
pub use digest::ElementDigest;

#[cfg(test)]
mod tests;

// CONSTANTS
// ================================================================================================

/// Sponge state is set to 12 field elements or 93 bytes; 8 elements are reserved for rate and
/// the remaining 4 elements are reserved for capacity.
const STATE_WIDTH: usize = 12;
const RATE_WIDTH: usize = 8;

/// The output of the hash function is a digest which consists of 4 field elements or 31 bytes.
const DIGEST_SIZE: usize = 4;

/// The number of rounds is set to 7 to target 124-bit security level with 40% security margin;
/// computed using algorithm 7 from <https://eprint.iacr.org/2020/1143.pdf>
const NUM_ROUNDS: usize = 7;

/// S-Box and Inverse S-Box powers;
/// computed using algorithm 6 from <https://eprint.iacr.org/2020/1143.pdf>
///
/// The constants are defined for tests only because the exponentiations in the code are unrolled
/// for efficiency reasons.
#[cfg(test)]
const ALPHA: u32 = 3;
#[cfg(test)]
const INV_ALPHA: u64 = 3074416663688030891;

// HASHER IMPLEMENTATION
// ================================================================================================

///
/// The hash function is implemented according to the Rescue Prime
/// [specifications](https://eprint.iacr.org/2020/1143.pdf) with the following exception:
/// * We set the number of rounds to 7, which implies a 40% security margin instead of the 50%
///   margin used in the specifications (a 50% margin rounds up to 8 rounds). The primary motivation
///   for this is that having the number of rounds be one less than a power of two simplifies AIR
///   design for computations involving the hash function.
/// * When hashing a sequence of elements, we do not append Fp(1) followed by Fp(0) elements to the
///   end of the sequence as padding. Instead, we initialize one of the capacity elements to the
///   number of elements to be hashed, and pad the sequence with Fp(0) elements only. This ensures
///   consistency of hash outputs between different hashing methods (see section below). However, it
///   also means that our instantiation of Rescue Prime cannot be used in a stream mode as the
///   number of elements to be hashed must be known upfront.
///
/// The parameters used to instantiate the function are:
/// * Field: 62-bit prime field with modulus 2^62 - 111 * 2^39 + 1.
/// * State width: 12 field elements.
/// * Capacity size: 4 field elements.
/// * Number of rounds: 7.
/// * S-Box degree: 3.
///
/// The above parameters target 124-bit security level. The digest consists of four field elements
/// and it can be serialized into 31 bytes (248 bits).
///
/// ## Hash output consistency
/// Functions [hash_elements()](Rp62_248::hash_elements), [merge()](Rp62_248::merge), and
/// [merge_with_int()](Rp62_248::merge_with_int) are internally consistent. That is, computing
/// a hash for the same set of elements using these functions will always produce the same
/// result. For example, merging two digests using [merge()](Rp62_248::merge) will produce the
/// same result as hashing 8 elements which make up these digests using
/// [hash_elements()](Rp62_248::hash_elements) function.
///
/// However, [hash()](Rp62_248::hash) function is not consistent with functions mentioned above.
/// For example, if we take two field elements, serialize them to bytes and hash them using
/// [hash()](Rp62_248::hash), the result will differ from the result obtained by hashing these
/// elements directly using [hash_elements()](Rp62_248::hash_elements) function. The reason for
/// this difference is that [hash()](Rp62_248::hash) function needs to be able to handle
/// arbitrary binary strings, which may or may not encode valid field elements - and thus,
/// deserialization procedure used by this function is different from the procedure used to
/// deserialize valid field elements.
///
/// Thus, if the underlying data consists of valid field elements, it might make more sense
/// to deserialize them into field elements and then hash them using
/// [hash_elements()](Rp62_248::hash_elements) function rather then hashing the serialized bytes
/// using [hash()](Rp62_248::hash) function.
pub struct Rp62_248();

    type Digest = ElementDigest;

    const COLLISION_RESISTANCE: u32 = 124;

    fn hash(bytes: &[u8]) -> Self::Digest {
        // compute the number of elements required to represent the string; we will be processing
        // the string in 7-byte chunks, thus the number of elements will be equal to the number
        // of such chunks (including a potential partial chunk at the end).
        let num_elements = if bytes.len() % 7 == 0 {
            bytes.len() / 7
        } else {
            bytes.len() / 7 + 1
        };

        // initialize state to all zeros, except for the last element of the capacity part, which
        // is set to the number of elements to be hashed. this is done so that adding zero elements
        // at the end of the list always results in a different hash.

        // break the string into 7-byte chunks, convert each chunk into a field element, and
        // absorb the element into the rate portion of the state. we use 7-byte chunks because
        // every 7-byte chunk is guaranteed to map to some field element.
        let mut i = 0;
        let mut buf = [0_u8; 8];
        for chunk in bytes.chunks(7) {
            if i < num_elements - 1 {
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
            // state; if the rate is filled up, apply the Rescue permutation and start absorbing
            // again from zero index.
            i += 1;
            if i % RATE_WIDTH == 0 {
                apply_permutation(&mut state);
                i = 0;
            }
        }

        // if we absorbed some elements but didn't apply a permutation to them (would happen when
        // the number of elements is not a multiple of RATE_WIDTH), apply the Rescue permutation.
        // we don't need to apply any extra padding because we injected total number of elements
        // in the input list into the capacity portion of the state during initialization.
        if i > 0 {
            apply_permutation(&mut state);
        }

        // return the first 4 elements of the state as hash result
        ElementDigest::new(state[..DIGEST_SIZE].try_into().unwrap())
    }

    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        // initialize the state by copying the digest elements into the rate portion of the state
        // (8 total elements), and set the last capacity element to 8 (the number of elements to
        // be hashed).
        state[..RATE_WIDTH].copy_from_slice(Self::Digest::digests_as_elements(values));

        // apply the Rescue permutation and return the first four elements of the state
        apply_permutation(&mut state);
        ElementDigest::new(state[..DIGEST_SIZE].try_into().unwrap())
    }

    fn merge_many(values: &[Self::Digest]) -> Self::Digest {
        Self::hash_elements(ElementDigest::digests_as_elements(values))
    }

    fn merge_with_int(seed: Self::Digest, value: u64) -> Self::Digest {
        // initialize the state as follows:
        // - seed is copied into the first 4 elements of the state.
        // - if the value fits into a single field element, copy it into the fifth state element and
        //   set the last capacity element to 5 (the number of elements to be hashed).
        // - if the value doesn't fit into a single field element, split it into two field elements,
        //   copy them into state elements 5 and 6, and set the last capacity element to 6.
        state[..DIGEST_SIZE].copy_from_slice(seed.as_elements());
        } else {
        }

        // apply the Rescue permutation and return the first four elements of the state
        apply_permutation(&mut state);
        ElementDigest::new(state[..DIGEST_SIZE].try_into().unwrap())
    }
}


        // convert the elements into a list of base field elements
        let elements = E::slice_as_base_elements(elements);

        // initialize state to all zeros, except for the last element of the capacity part, which
        // is set to the number of elements to be hashed. this is done so that adding zero elements
        // at the end of the list always results in a different hash.

        // absorb elements into the state one by one until the rate portion of the state is filled
        // up; then apply the Rescue permutation and start absorbing again; repeat until all
        // elements have been absorbed
        let mut i = 0;
        for &element in elements.iter() {
            state[i] += element;
            i += 1;
            if i % RATE_WIDTH == 0 {
                apply_permutation(&mut state);
                i = 0;
            }
        }

        // if we absorbed some elements but didn't apply a permutation to them (would happen when
        // the number of elements is not a multiple of RATE_WIDTH), apply the Rescue permutation.
        // we don't need to apply any extra padding because we injected total number of elements
        // in the input list into the capacity portion of the state during initialization.
        if i > 0 {
            apply_permutation(&mut state);
        }

        // return the first 4 elements of the state as hash result
        ElementDigest::new(state[..DIGEST_SIZE].try_into().unwrap())
    }
}

// RESCUE PERMUTATION
// ================================================================================================

/// Applies Rescue-XLIX permutation to the provided state.
///
/// Implementation is based on algorithm 3 from <https://eprint.iacr.org/2020/1143.pdf>
    // apply round function 7 times; this provides 128-bit security with 40% security margin
    for i in 0..NUM_ROUNDS {
        apply_round(state, i);
    }
}

/// Rescue-XLIX round function.
#[inline(always)]
    // apply first half of Rescue round
    apply_sbox(state);
    apply_mds(state);
    add_constants(state, &ARK1[round]);

    // apply second half of Rescue round
    apply_inv_sbox(state);
    apply_mds(state);
    add_constants(state, &ARK2[round]);
}

// HELPER FUNCTIONS
// ================================================================================================

#[inline(always)]
    result.iter_mut().zip(MDS).for_each(|(r, mds_row)| {
        state.iter().zip(mds_row).for_each(|(&s, m)| {
            *r += m * s;
        });
    });
    *state = result
}

#[inline(always)]
    state.iter_mut().zip(ark).for_each(|(s, &k)| *s += k);
}

#[inline(always)]
    state.iter_mut().for_each(|v| *v = v.cube())
}

#[inline(always)]
    // compute base^3074416663688030891 using 69 multiplications per array element
    // 3074416663688030891 = b10101010101010100001011010101010101010101010101010101010101011

    // compute base^10
    let mut t1 = *state;
    t1.iter_mut().for_each(|t1| *t1 = t1.square());

    // compute base^1010

    // compute base^10101010

    // compute base^1010101010101010

    // compute base^10101010101010100001010

    // compute base^10101010101010100001011010101010101010

    // compute base^101010101010101000010110101010101010101010101010101010

    // compute base^10101010101010100001011010101010101010101010101010101010101010

    // compute base^10101010101010100001011010101010101010101010101010101010101011
    state.iter_mut().zip(acc).for_each(|(s, a)| *s *= a);
}

// MDS
// ================================================================================================
/// Rescue MDS matrix
/// Computed using algorithm 4 from <https://eprint.iacr.org/2020/1143.pdf>
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
