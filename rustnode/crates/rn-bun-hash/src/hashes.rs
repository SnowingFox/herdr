//! The named variants under `Bun.hash.*`, transcribed from Bun 1.4.4.
//!
//! Each of these is a standard algorithm whose reference implementation Bun
//! carries in `src/hash/`, with one exception: `xxHash3` comes from Bun's
//! Highway-dispatched C++ (`src/jsc/bindings/xxhash3.cpp`) and is the scalar
//! XXH3_64bits, which is what the reference produces on every target.
//!
//! # Seeds are not uniform
//!
//! The four seed behaviours below are all measured, and a shared "read the seed
//! as u64" helper is wrong for three of them:
//!
//! | member | seed |
//! | --- | --- |
//! | `adler32`, `cityHash32` | ignored entirely |
//! | `crc32`, `xxHash3` | truncated to 32 bits |
//! | `cityHash64`, `xxHash64`, `murmur64v2`, `rapidhash`, `wyhash` | full 64 bits |
//! | `xxHash32`, `murmur32v2`, `murmur32v3` | truncated to 32 bits |
//!
//! The truncations come from `HashObject.rs`'s `seed_of(...) as u32`, not from
//! the algorithms, so they belong at this boundary and not inside e.g.
//! [`xxhash3`].

// ---------------------------------------------------------------------------
// Adler-32
// ---------------------------------------------------------------------------

/// `Bun.hash.adler32`. No seed: the JS binding takes one argument.
///
/// This is `src/hash/adler32.rs` including its `NMAX` batching. The batching is
/// not an optimisation that can be skipped for short inputs: `s1` and `s2` are
/// only reduced modulo `BASE` at the end of each 5552-byte batch, so a
/// per-byte-modulo version produces the same answer but a version that reduces
/// at different points could overflow `u32` on a long input. Keeping the shape
/// means the overflow behaviour is the reference's.
pub fn adler32(input: &[u8]) -> u32 {
    const BASE: u32 = 65521;
    const NMAX: usize = 5552;
    permute_adler(1, input, BASE, NMAX)
}

fn permute_adler(state: u32, input: &[u8], base: u32, nmax: usize) -> u32 {
    let mut s1 = state & 0xffff;
    let mut s2 = (state >> 16) & 0xffff;

    if input.len() == 1 {
        s1 = s1.wrapping_add(input[0] as u32);
        if s1 >= base {
            s1 -= base;
        }
        s2 = s2.wrapping_add(s1);
        if s2 >= base {
            s2 -= base;
        }
    } else if input.len() < 16 {
        for &byte in input {
            s1 = s1.wrapping_add(byte as u32);
            s2 = s2.wrapping_add(s1);
        }
        if s1 >= base {
            s1 -= base;
        }
        s2 %= base;
    } else {
        const N: usize = 5552 / 16;

        let mut i = 0usize;
        while i + nmax <= input.len() {
            let mut rounds = 0usize;
            while rounds < N {
                for j in 0..16usize {
                    s1 = s1.wrapping_add(input[i + j] as u32);
                    s2 = s2.wrapping_add(s1);
                }
                i += 16;
                rounds += 1;
            }
            s1 %= base;
            s2 %= base;
        }

        if i < input.len() {
            while i + 16 <= input.len() {
                for j in 0..16usize {
                    s1 = s1.wrapping_add(input[i + j] as u32);
                    s2 = s2.wrapping_add(s1);
                }
                i += 16;
            }
            while i < input.len() {
                s1 = s1.wrapping_add(input[i] as u32);
                s2 = s2.wrapping_add(s1);
                i += 1;
            }
            s1 %= base;
            s2 %= base;
        }
    }

    s1 | (s2 << 16)
}

// ---------------------------------------------------------------------------
// MurmurHash
// ---------------------------------------------------------------------------

#[inline(always)]
fn read_u32_le(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

#[inline(always)]
fn read_u64_le(bytes: &[u8]) -> u64 {
    let mut words = [0u8; 8];
    words.copy_from_slice(&bytes[..8]);
    u64::from_le_bytes(words)
}

/// `Bun.hash.murmur32v2`.
///
/// The length is truncated to `u32` before it enters the state. That is a real
/// quirk of the reference — it keeps a >4 GiB input hashing the way it always
/// has — so it is reproduced rather than corrected.
pub fn murmur32v2(input: &[u8], seed: u32) -> u32 {
    const M: u32 = 0x5bd1_e995;
    let len = input.len() as u32;
    let mut h1: u32 = seed ^ len;

    let blocks = (len >> 2) as usize;
    for i in 0..blocks {
        let mut k1 = read_u32_le(&input[i * 4..]);
        k1 = k1.wrapping_mul(M);
        k1 ^= k1 >> 24;
        k1 = k1.wrapping_mul(M);
        h1 = h1.wrapping_mul(M);
        h1 ^= k1;
    }

    let offset = (len & 0xffff_fffc) as usize;
    let rest = len & 3;
    if rest >= 3 {
        h1 ^= (input[offset + 2] as u32) << 16;
    }
    if rest >= 2 {
        h1 ^= (input[offset + 1] as u32) << 8;
    }
    if rest >= 1 {
        h1 ^= input[offset] as u32;
        h1 = h1.wrapping_mul(M);
    }
    h1 ^= h1 >> 13;
    h1 = h1.wrapping_mul(M);
    h1 ^= h1 >> 15;
    h1
}

/// `Bun.hash.murmur64v2`.
pub fn murmur64v2(input: &[u8], seed: u64) -> u64 {
    const M: u64 = 0xc6a4_a793_5bd1_e995;
    let mut h1: u64 = seed ^ (input.len() as u64).wrapping_mul(M);

    let blocks = input.len() / 8;
    for i in 0..blocks {
        let mut k1 = read_u64_le(&input[i * 8..]);
        k1 = k1.wrapping_mul(M);
        k1 ^= k1 >> 47;
        k1 = k1.wrapping_mul(M);
        h1 ^= k1;
        h1 = h1.wrapping_mul(M);
    }

    let rest = input.len() & 7;
    let offset = input.len() - rest;
    if rest > 0 {
        let mut tail = [0u8; 8];
        tail[..rest].copy_from_slice(&input[offset..]);
        h1 ^= u64::from_le_bytes(tail);
        h1 = h1.wrapping_mul(M);
    }
    h1 ^= h1 >> 47;
    h1 = h1.wrapping_mul(M);
    h1 ^= h1 >> 47;
    h1
}

/// Murmur3's 32-bit finaliser, also `CityHash32::fmix`.
#[inline(always)]
fn fmix32(mut h: u32) -> u32 {
    h ^= h >> 16;
    h = h.wrapping_mul(0x85eb_ca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2_ae35);
    h ^ (h >> 16)
}

/// `Bun.hash.murmur32v3`.
pub fn murmur32v3(input: &[u8], seed: u32) -> u32 {
    const C1: u32 = 0xcc9e_2d51;
    const C2: u32 = 0x1b87_3593;
    let len = input.len() as u32;
    let mut h1: u32 = seed;

    let blocks = (len >> 2) as usize;
    for i in 0..blocks {
        let mut k1 = read_u32_le(&input[i * 4..]);
        k1 = k1.wrapping_mul(C1);
        k1 = k1.rotate_left(15);
        k1 = k1.wrapping_mul(C2);
        h1 ^= k1;
        h1 = h1.rotate_left(13);
        h1 = h1.wrapping_mul(5).wrapping_add(0xe654_6b64);
    }

    let mut k1: u32 = 0;
    let offset = (len & 0xffff_fffc) as usize;
    let rest = len & 3;
    if rest == 3 {
        k1 ^= (input[offset + 2] as u32) << 16;
    }
    if rest >= 2 {
        k1 ^= (input[offset + 1] as u32) << 8;
    }
    if rest >= 1 {
        k1 ^= input[offset] as u32;
        k1 = k1.wrapping_mul(C1);
        k1 = k1.rotate_left(15);
        k1 = k1.wrapping_mul(C2);
        h1 ^= k1;
    }

    h1 ^= len;
    fmix32(h1)
}

// ---------------------------------------------------------------------------
// xxHash
// ---------------------------------------------------------------------------

const PRIME32_1: u32 = 0x9E37_79B1;
const PRIME32_2: u32 = 0x85EB_CA77;
const PRIME32_3: u32 = 0xC2B2_AE3D;
const PRIME32_4: u32 = 0x27D4_EB2F;
const PRIME32_5: u32 = 0x1656_67B1;

const PRIME64_1: u64 = 0x9E37_79B1_85EB_CA87;
const PRIME64_2: u64 = 0xC2B2_AE3D_27D4_EB4F;
const PRIME64_3: u64 = 0x1656_67B1_9E37_79F9;
const PRIME64_4: u64 = 0x85EB_CA77_C2B2_AE63;
const PRIME64_5: u64 = 0x27D4_EB2F_1656_67C5;

#[inline(always)]
fn xxh32_round(acc: u32, input: u32) -> u32 {
    acc.wrapping_add(input.wrapping_mul(PRIME32_2))
        .rotate_left(13)
        .wrapping_mul(PRIME32_1)
}

#[inline(always)]
fn xxh32_avalanche(mut h: u32) -> u32 {
    h ^= h >> 15;
    h = h.wrapping_mul(PRIME32_2);
    h ^= h >> 13;
    h = h.wrapping_mul(PRIME32_3);
    h ^= h >> 16;
    h
}

fn xxh32_finalize(mut h: u32, mut rest: &[u8]) -> u32 {
    while rest.len() >= 4 {
        h = h.wrapping_add(read_u32_le(rest).wrapping_mul(PRIME32_3));
        rest = &rest[4..];
        h = h.rotate_left(17).wrapping_mul(PRIME32_4);
    }
    for &byte in rest {
        h = h.wrapping_add((byte as u32).wrapping_mul(PRIME32_5));
        h = h.rotate_left(11).wrapping_mul(PRIME32_1);
    }
    xxh32_avalanche(h)
}

/// `Bun.hash.xxHash32`.
pub fn xxhash32(input: &[u8], seed: u32) -> u32 {
    let mut h;
    let mut rest = input;
    if input.len() >= 16 {
        let mut v1 = seed.wrapping_add(PRIME32_1).wrapping_add(PRIME32_2);
        let mut v2 = seed.wrapping_add(PRIME32_2);
        let mut v3 = seed;
        let mut v4 = seed.wrapping_sub(PRIME32_1);
        while rest.len() >= 16 {
            v1 = xxh32_round(v1, read_u32_le(rest));
            v2 = xxh32_round(v2, read_u32_le(&rest[4..]));
            v3 = xxh32_round(v3, read_u32_le(&rest[8..]));
            v4 = xxh32_round(v4, read_u32_le(&rest[12..]));
            rest = &rest[16..];
        }
        h = v1
            .rotate_left(1)
            .wrapping_add(v2.rotate_left(7))
            .wrapping_add(v3.rotate_left(12))
            .wrapping_add(v4.rotate_left(18));
    } else {
        h = seed.wrapping_add(PRIME32_5);
    }
    h = h.wrapping_add(input.len() as u32);
    xxh32_finalize(h, rest)
}

#[inline(always)]
fn xxh64_round(acc: u64, input: u64) -> u64 {
    acc.wrapping_add(input.wrapping_mul(PRIME64_2))
        .rotate_left(31)
        .wrapping_mul(PRIME64_1)
}

#[inline(always)]
fn xxh64_merge_round(acc: u64, value: u64) -> u64 {
    let value = xxh64_round(0, value);
    let acc = acc ^ value;
    acc.wrapping_mul(PRIME64_1).wrapping_add(PRIME64_4)
}

#[inline(always)]
fn xxh64_avalanche(mut h: u64) -> u64 {
    h ^= h >> 33;
    h = h.wrapping_mul(PRIME64_2);
    h ^= h >> 29;
    h = h.wrapping_mul(PRIME64_3);
    h ^= h >> 32;
    h
}

fn xxh64_finalize(mut h: u64, mut rest: &[u8]) -> u64 {
    while rest.len() >= 8 {
        let k1 = xxh64_round(0, read_u64_le(rest));
        rest = &rest[8..];
        h ^= k1;
        h = h
            .rotate_left(27)
            .wrapping_mul(PRIME64_1)
            .wrapping_add(PRIME64_4);
    }
    if rest.len() >= 4 {
        h ^= u64::from(read_u32_le(rest)).wrapping_mul(PRIME64_1);
        rest = &rest[4..];
        h = h
            .rotate_left(23)
            .wrapping_mul(PRIME64_2)
            .wrapping_add(PRIME64_3);
    }
    for &byte in rest {
        h ^= u64::from(byte).wrapping_mul(PRIME64_5);
        h = h.rotate_left(11).wrapping_mul(PRIME64_1);
    }
    xxh64_avalanche(h)
}

/// `Bun.hash.xxHash64`.
pub fn xxhash64(input: &[u8], seed: u64) -> u64 {
    let mut h;
    let mut rest = input;
    if input.len() >= 32 {
        let mut v1 = seed.wrapping_add(PRIME64_1).wrapping_add(PRIME64_2);
        let mut v2 = seed.wrapping_add(PRIME64_2);
        let mut v3 = seed;
        let mut v4 = seed.wrapping_sub(PRIME64_1);
        while rest.len() >= 32 {
            v1 = xxh64_round(v1, read_u64_le(rest));
            v2 = xxh64_round(v2, read_u64_le(&rest[8..]));
            v3 = xxh64_round(v3, read_u64_le(&rest[16..]));
            v4 = xxh64_round(v4, read_u64_le(&rest[24..]));
            rest = &rest[32..];
        }
        h = v1
            .rotate_left(1)
            .wrapping_add(v2.rotate_left(7))
            .wrapping_add(v3.rotate_left(12))
            .wrapping_add(v4.rotate_left(18));
        h = xxh64_merge_round(h, v1);
        h = xxh64_merge_round(h, v2);
        h = xxh64_merge_round(h, v3);
        h = xxh64_merge_round(h, v4);
    } else {
        h = seed.wrapping_add(PRIME64_5);
    }
    h = h.wrapping_add(input.len() as u64);
    xxh64_finalize(h, rest)
}

// ---------------------------------------------------------------------------
// XXH3
// ---------------------------------------------------------------------------

/// `XXH3_kSecret`, byte-for-byte the xxHash reference default secret.
const XXH3_SECRET: [u8; 192] = [
    0xb8, 0xfe, 0x6c, 0x39, 0x23, 0xa4, 0x4b, 0xbe, 0x7c, 0x01, 0x81, 0x2c, 0xf7, 0x21, 0xad, 0x1c,
    0xde, 0xd4, 0x6d, 0xe9, 0x83, 0x90, 0x97, 0xdb, 0x72, 0x40, 0xa4, 0xa4, 0xb7, 0xb3, 0x67, 0x1f,
    0xcb, 0x79, 0xe6, 0x4e, 0xcc, 0xc0, 0xe5, 0x78, 0x82, 0x5a, 0xd0, 0x7d, 0xcc, 0xff, 0x72, 0x21,
    0xb8, 0x08, 0x46, 0x74, 0xf7, 0x43, 0x24, 0x8e, 0xe0, 0x35, 0x90, 0xe6, 0x81, 0x3a, 0x26, 0x4c,
    0x3c, 0x28, 0x52, 0xbb, 0x91, 0xc3, 0x00, 0xcb, 0x88, 0xd0, 0x65, 0x8b, 0x1b, 0x53, 0x2e, 0xa3,
    0x71, 0x64, 0x48, 0x97, 0xa2, 0x0d, 0xf9, 0x4e, 0x38, 0x19, 0xef, 0x46, 0xa9, 0xde, 0xac, 0xd8,
    0xa8, 0xfa, 0x76, 0x3f, 0xe3, 0x9c, 0x34, 0x3f, 0xf9, 0xdc, 0xbb, 0xc7, 0xc7, 0x0b, 0x4f, 0x1d,
    0x8a, 0x51, 0xe0, 0x4b, 0xcd, 0xb4, 0x59, 0x31, 0xc8, 0x9f, 0x7e, 0xc9, 0xd9, 0x78, 0x73, 0x64,
    0xea, 0xc5, 0xac, 0x83, 0x34, 0xd3, 0xeb, 0xc3, 0xc5, 0x81, 0xa0, 0xff, 0xfa, 0x13, 0x63, 0xeb,
    0x17, 0x0d, 0xdd, 0x51, 0xb7, 0xf0, 0xda, 0x49, 0xd3, 0x16, 0x55, 0x26, 0x29, 0xd4, 0x68, 0x9e,
    0x2b, 0x16, 0xbe, 0x58, 0x7d, 0x47, 0xa1, 0xfc, 0x8f, 0xf8, 0xb8, 0xd1, 0x7a, 0xd0, 0x31, 0xce,
    0x45, 0xcb, 0x3a, 0x8f, 0x95, 0x16, 0x04, 0x28, 0xaf, 0xd7, 0xfb, 0xca, 0xbb, 0x4b, 0x40, 0x7e,
];

const XXH_STRIPE_LEN: usize = 64;
const XXH_SECRET_CONSUME_RATE: usize = 8;
const XXH_ACC_NB: usize = XXH_STRIPE_LEN / 8;
const XXH_SECRET_LASTACC_START: usize = 7;
const XXH_SECRET_MERGEACCS_START: usize = 11;
const XXH3_MIDSIZE_MAX: usize = 240;
const XXH3_SECRET_SIZE_MIN: usize = 136;
const PRIME_MX1: u64 = 0x1656_6791_9E37_79F9;
const PRIME_MX2: u64 = 0x9FB2_1C65_1E98_DF25;

#[inline(always)]
fn xorshift(value: u64, shift: u32) -> u64 {
    value ^ (value >> shift)
}

#[inline(always)]
fn avalanche(mut h: u64) -> u64 {
    h = xorshift(h, 37);
    h = h.wrapping_mul(PRIME_MX1);
    xorshift(h, 32)
}

#[inline(always)]
fn rrmxmx(mut h: u64, len: u64) -> u64 {
    h ^= h.rotate_left(49) ^ h.rotate_left(24);
    h = h.wrapping_mul(PRIME_MX2);
    h ^= (h >> 35).wrapping_add(len);
    h = h.wrapping_mul(PRIME_MX2);
    xorshift(h, 28)
}

#[inline(always)]
fn mul128_fold64(lhs: u64, rhs: u64) -> u64 {
    let product = (lhs as u128).wrapping_mul(rhs as u128);
    (product as u64) ^ ((product >> 64) as u64)
}

#[inline(always)]
fn mix16(input: &[u8], secret: &[u8], seed: u64) -> u64 {
    mul128_fold64(
        read_u64_le(input) ^ read_u64_le(secret).wrapping_add(seed),
        read_u64_le(&input[8..]) ^ read_u64_le(&secret[8..]).wrapping_sub(seed),
    )
}

fn len_0_to_16(input: &[u8], secret: &[u8], seed: u64) -> u64 {
    let len = input.len();
    if len > 8 {
        let bitflip1 = (read_u64_le(&secret[24..]) ^ read_u64_le(&secret[32..])).wrapping_add(seed);
        let bitflip2 = (read_u64_le(&secret[40..]) ^ read_u64_le(&secret[48..])).wrapping_sub(seed);
        let input_lo = read_u64_le(input) ^ bitflip1;
        let input_hi = read_u64_le(&input[len - 8..]) ^ bitflip2;
        let acc = (len as u64)
            .wrapping_add(input_lo.swap_bytes())
            .wrapping_add(input_hi)
            .wrapping_add(mul128_fold64(input_lo, input_hi));
        return avalanche(acc);
    }
    if len >= 4 {
        // `XXH3_avalanche`'s 4..8 branch folds the seed with its own
        // **byte-swapped** low half. Reading the low 32 bits back in the same
        // order is a no-op and produces a different hash from `seed != 0` while
        // agreeing at `seed == 0`, which is why the mistake survived: the
        // measured seed-0 vectors all pass either way.
        let seed = seed ^ ((u32::from_be_bytes((seed as u32).to_le_bytes()) as u64) << 32);
        let input1 = u32::from_le_bytes([input[0], input[1], input[2], input[3]]);
        let tail = &input[len - 4..];
        let input2 = u32::from_le_bytes([tail[0], tail[1], tail[2], tail[3]]);
        let bitflip = (read_u64_le(&secret[8..]) ^ read_u64_le(&secret[16..])).wrapping_sub(seed);
        let input64 = u64::from(input2).wrapping_add(u64::from(input1) << 32);
        return rrmxmx(input64 ^ bitflip, len as u64);
    }
    if len > 0 {
        let c1 = input[0];
        let c2 = input[len >> 1];
        let c3 = input[len - 1];
        let combined =
            (u32::from(c1) << 16) | (u32::from(c2) << 24) | u32::from(c3) | ((len as u32) << 8);
        let low = u32::from_le_bytes([secret[0], secret[1], secret[2], secret[3]]);
        let high = u32::from_le_bytes([secret[4], secret[5], secret[6], secret[7]]);
        let bitflip = u64::from(low ^ high).wrapping_add(seed);
        return xxh64_avalanche(u64::from(combined) ^ bitflip);
    }
    xxh64_avalanche(seed ^ (read_u64_le(&secret[56..]) ^ read_u64_le(&secret[64..])))
}

fn len_17_to_128(input: &[u8], secret: &[u8], seed: u64) -> u64 {
    let len = input.len();
    let mut acc = (len as u64).wrapping_mul(PRIME64_1);
    if len > 32 {
        if len > 64 {
            if len > 96 {
                acc = acc.wrapping_add(mix16(&input[48..], &secret[96..], seed));
                acc = acc.wrapping_add(mix16(&input[len - 64..], &secret[112..], seed));
            }
            acc = acc.wrapping_add(mix16(&input[32..], &secret[64..], seed));
            acc = acc.wrapping_add(mix16(&input[len - 48..], &secret[80..], seed));
        }
        acc = acc.wrapping_add(mix16(&input[16..], &secret[32..], seed));
        acc = acc.wrapping_add(mix16(&input[len - 32..], &secret[48..], seed));
    }
    acc = acc.wrapping_add(mix16(input, secret, seed));
    acc = acc.wrapping_add(mix16(&input[len - 16..], &secret[16..], seed));
    avalanche(acc)
}

fn len_129_to_240(input: &[u8], secret: &[u8], seed: u64) -> u64 {
    const START_OFFSET: usize = 3;
    const LAST_OFFSET: usize = 17;
    let len = input.len();

    let mut acc = (len as u64).wrapping_mul(PRIME64_1);
    let rounds = len / 16;
    for i in 0..8 {
        acc = acc.wrapping_add(mix16(&input[16 * i..], &secret[16 * i..], seed));
    }
    let mut acc_end = mix16(
        &input[len - 16..],
        &secret[XXH3_SECRET_SIZE_MIN - LAST_OFFSET..],
        seed,
    );
    acc = avalanche(acc);
    for i in 8..rounds {
        acc_end = acc_end.wrapping_add(mix16(
            &input[16 * i..],
            &secret[(16 * (i - 8)) + START_OFFSET..],
            seed,
        ));
    }
    avalanche(acc.wrapping_add(acc_end))
}

/// `XXH3_accumulate_512`, per 64-bit lane. The scalar form of what Bun's
/// Highway kernel vectorises; only the stripe loop differs, and the per-lane
/// arithmetic is what decides the number.
fn accumulate_512(acc: &mut [u64; XXH_ACC_NB], input: &[u8], secret: &[u8]) {
    for i in 0..XXH_ACC_NB {
        let data = read_u64_le(&input[i * 8..]);
        let key = read_u64_le(&secret[i * 8..]);
        let data_key = data ^ key;
        let product = (data_key & 0xffff_ffff).wrapping_mul(data_key >> 32);
        // `acc[lane ^ 1]`: the reference swaps adjacent lanes, which is what a
        // 128-bit shuffle does in the vector form.
        let swapped = read_u64_le(&input[(i ^ 1) * 8..]);
        acc[i] = acc[i].wrapping_add(swapped).wrapping_add(product);
    }
}

/// `XXH3_scrambleAcc`.
fn scramble_acc(acc: &mut [u64; XXH_ACC_NB], secret: &[u8]) {
    for i in 0..XXH_ACC_NB {
        let mut lane = acc[i];
        let key = read_u64_le(&secret[i * 8..]);
        lane = xorshift(lane, 47);
        lane ^= key;
        // The reference multiplies by `PRIME32_1` as a 32-bit constant, done here
        // as two 32×32 halves so the 64-bit product keeps its low word.
        let lo = (lane & 0xffff_ffff).wrapping_mul(u64::from(PRIME32_1));
        let hi = (lane >> 32).wrapping_mul(u64::from(PRIME32_1));
        acc[i] = lo.wrapping_add(hi << 32);
    }
}

fn merge_accs(acc: &[u64; XXH_ACC_NB], secret: &[u8], start: u64) -> u64 {
    let mut result = start;
    for i in 0..4 {
        result = result.wrapping_add(mul128_fold64(
            acc[2 * i] ^ read_u64_le(&secret[16 * i..]),
            acc[2 * i + 1] ^ read_u64_le(&secret[16 * i + 8..]),
        ));
    }
    avalanche(result)
}

fn init_custom_secret(secret: &mut [u8; 192], seed: u64) {
    for i in 0..(192 / 16) {
        let lo = read_u64_le(&XXH3_SECRET[16 * i..]).wrapping_add(seed);
        let hi = read_u64_le(&XXH3_SECRET[16 * i + 8..]).wrapping_sub(seed);
        secret[16 * i..16 * i + 8].copy_from_slice(&lo.to_le_bytes());
        secret[16 * i + 8..16 * i + 16].copy_from_slice(&hi.to_le_bytes());
    }
}

fn hash_long(input: &[u8], secret: &[u8]) -> u64 {
    let mut acc = [
        u64::from(PRIME32_3),
        PRIME64_1,
        PRIME64_2,
        PRIME64_3,
        PRIME64_4,
        u64::from(PRIME32_2),
        PRIME64_5,
        u64::from(PRIME32_1),
    ];

    let len = input.len();
    let stripes_per_block = (192 - XXH_STRIPE_LEN) / XXH_SECRET_CONSUME_RATE;
    let block_len = XXH_STRIPE_LEN * stripes_per_block;
    let blocks = (len - 1) / block_len;

    for n in 0..blocks {
        let block = &input[n * block_len..];
        for s in 0..stripes_per_block {
            accumulate_512(
                &mut acc,
                &block[s * XXH_STRIPE_LEN..],
                &secret[s * XXH_SECRET_CONSUME_RATE..],
            );
        }
        scramble_acc(&mut acc, &secret[192 - XXH_STRIPE_LEN..]);
    }

    let stripes = ((len - 1) - (block_len * blocks)) / XXH_STRIPE_LEN;
    let last_block = &input[blocks * block_len..];
    for s in 0..stripes {
        accumulate_512(
            &mut acc,
            &last_block[s * XXH_STRIPE_LEN..],
            &secret[s * XXH_SECRET_CONSUME_RATE..],
        );
    }

    // The last 64 bytes always go through the tail secret, whatever the block
    // arithmetic landed on.
    accumulate_512(
        &mut acc,
        &input[len - XXH_STRIPE_LEN..],
        &secret[192 - XXH_STRIPE_LEN - XXH_SECRET_LASTACC_START..],
    );

    merge_accs(
        &acc,
        &secret[XXH_SECRET_MERGEACCS_START..],
        (len as u64).wrapping_mul(PRIME64_1),
    )
}

/// `XXH3_64bits_withSeed` — `Bun.hash.xxHash3`.
pub fn xxhash3(input: &[u8], seed: u64) -> u64 {
    let len = input.len();
    if len <= 16 {
        return len_0_to_16(input, &XXH3_SECRET, seed);
    }
    if len <= 128 {
        return len_17_to_128(input, &XXH3_SECRET, seed);
    }
    if len <= XXH3_MIDSIZE_MAX {
        return len_129_to_240(input, &XXH3_SECRET, seed);
    }
    if seed == 0 {
        return hash_long(input, &XXH3_SECRET);
    }
    let mut custom = [0u8; 192];
    init_custom_secret(&mut custom, seed);
    hash_long(input, &custom)
}

// ---------------------------------------------------------------------------
// CityHash
// ---------------------------------------------------------------------------

#[inline(always)]
fn fetch32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

#[inline(always)]
fn fetch64(bytes: &[u8], offset: usize) -> u64 {
    read_u64_le(&bytes[offset..])
}

const CITY_C1: u32 = 0xcc9e_2d51;
const CITY_C2: u32 = 0x1b87_3593;

/// Murmur3's combining helper, which CityHash32 uses six times over.
#[inline(always)]
fn city_mur(a: u32, h: u32) -> u32 {
    let a = a
        .wrapping_mul(CITY_C1)
        .rotate_right(17)
        .wrapping_mul(CITY_C2);
    let h = h ^ a;
    h.rotate_right(19).wrapping_mul(5).wrapping_add(0xe654_6b64)
}

fn city_hash32_len_0_to_4(input: &[u8]) -> u32 {
    let len = input.len() as u32;
    let mut b: u32 = 0;
    let mut c: u32 = 9;
    for &byte in input {
        // Sign-extended, which is what the reference's `signed char` does.
        b = b
            .wrapping_mul(CITY_C1)
            .wrapping_add(byte as i8 as i32 as u32);
        c ^= b;
    }
    fmix32(city_mur(b, city_mur(len, c)))
}

fn city_hash32_len_5_to_12(input: &[u8]) -> u32 {
    let mut a = input.len() as u32;
    let mut b = a.wrapping_mul(5);
    let mut c: u32 = 9;
    let d = b;

    a = a.wrapping_add(fetch32(input, 0));
    b = b.wrapping_add(fetch32(input, input.len() - 4));
    c = c.wrapping_add(fetch32(input, (input.len() >> 1) & 4));

    fmix32(city_mur(c, city_mur(b, city_mur(a, d))))
}

fn city_hash32_len_13_to_24(input: &[u8]) -> u32 {
    let len = input.len() as u32;
    let a = fetch32(input, (input.len() >> 1) - 4);
    let b = fetch32(input, 4);
    let c = fetch32(input, input.len() - 8);
    let d = fetch32(input, input.len() >> 1);
    let e = fetch32(input, 0);
    let f = fetch32(input, input.len() - 4);

    fmix32(city_mur(
        f,
        city_mur(e, city_mur(d, city_mur(c, city_mur(b, city_mur(a, len))))),
    ))
}

/// `Bun.hash.cityHash32`. The JS seed is ignored, which is why this takes none.
pub fn city_hash32(input: &[u8]) -> u32 {
    if input.len() <= 24 {
        if input.len() <= 4 {
            return city_hash32_len_0_to_4(input);
        }
        if input.len() <= 12 {
            return city_hash32_len_5_to_12(input);
        }
        return city_hash32_len_13_to_24(input);
    }

    let len = input.len() as u32;
    let mut h: u32 = len;
    let mut g: u32 = CITY_C1.wrapping_mul(len);
    let mut f: u32 = g;

    let a0 = fetch32(input, input.len() - 4)
        .wrapping_mul(CITY_C1)
        .rotate_right(17)
        .wrapping_mul(CITY_C2);
    let a1 = fetch32(input, input.len() - 8)
        .wrapping_mul(CITY_C1)
        .rotate_right(17)
        .wrapping_mul(CITY_C2);
    let a2 = fetch32(input, input.len() - 16)
        .wrapping_mul(CITY_C1)
        .rotate_right(17)
        .wrapping_mul(CITY_C2);
    let a3 = fetch32(input, input.len() - 12)
        .wrapping_mul(CITY_C1)
        .rotate_right(17)
        .wrapping_mul(CITY_C2);
    let a4 = fetch32(input, input.len() - 20)
        .wrapping_mul(CITY_C1)
        .rotate_right(17)
        .wrapping_mul(CITY_C2);

    h ^= a0;
    h = h.rotate_right(19).wrapping_mul(5).wrapping_add(0xe654_6b64);
    h ^= a2;
    h = h.rotate_right(19).wrapping_mul(5).wrapping_add(0xe654_6b64);
    g ^= a1;
    g = g.rotate_right(19).wrapping_mul(5).wrapping_add(0xe654_6b64);
    g ^= a3;
    g = g.rotate_right(19).wrapping_mul(5).wrapping_add(0xe654_6b64);
    f = f.wrapping_add(a4);
    f = f.rotate_right(19).wrapping_mul(5).wrapping_add(0xe654_6b64);

    let mut iterations = (input.len() - 1) / 20;
    let mut offset = 0usize;
    while iterations != 0 {
        let b0 = fetch32(input, offset)
            .wrapping_mul(CITY_C1)
            .rotate_right(17)
            .wrapping_mul(CITY_C2);
        let b1 = fetch32(input, offset + 4);
        let b2 = fetch32(input, offset + 8)
            .wrapping_mul(CITY_C1)
            .rotate_right(17)
            .wrapping_mul(CITY_C2);
        let b3 = fetch32(input, offset + 12)
            .wrapping_mul(CITY_C1)
            .rotate_right(17)
            .wrapping_mul(CITY_C2);
        let b4 = fetch32(input, offset + 16);

        h ^= b0;
        h = h.rotate_right(18).wrapping_mul(5).wrapping_add(0xe654_6b64);
        f = f.wrapping_add(b1);
        f = f.rotate_right(19).wrapping_mul(CITY_C1);
        g = g.wrapping_add(b2);
        g = g.rotate_right(18).wrapping_mul(5).wrapping_add(0xe654_6b64);
        h ^= b3.wrapping_add(b1);
        h = h.rotate_right(19).wrapping_mul(5).wrapping_add(0xe654_6b64);
        g ^= b4;
        g = g.swap_bytes().wrapping_mul(5);
        h = h.wrapping_add(b4.wrapping_mul(5));
        h = h.swap_bytes();
        f = f.wrapping_add(b0);
        let tmp = h;
        h = f;
        f = g;
        g = tmp;
        offset += 20;
        iterations -= 1;
    }

    g = g.rotate_right(11).wrapping_mul(CITY_C1);
    g = g.rotate_right(17).wrapping_mul(CITY_C1);
    f = f.rotate_right(11).wrapping_mul(CITY_C1);
    f = f.rotate_right(17).wrapping_mul(CITY_C1);
    h = h.wrapping_add(g).rotate_right(19);
    h = h.wrapping_mul(5).wrapping_add(0xe654_6b64);
    h = h.rotate_right(17).wrapping_mul(CITY_C1);
    h = h.wrapping_add(f).rotate_right(19);
    h = h.wrapping_mul(5).wrapping_add(0xe654_6b64);
    h.rotate_right(17).wrapping_mul(CITY_C1)
}

const CITY_K0: u64 = 0xc3a5_c85c_97cb_3127;
const CITY_K1: u64 = 0xb492_b66f_be98_f273;
const CITY_K2: u64 = 0x9ae1_6a3b_2f90_404f;

#[inline(always)]
fn shift_mix(value: u64) -> u64 {
    value ^ (value >> 47)
}

#[inline(always)]
fn city_hash_len_16_mul(low: u64, high: u64, mul: u64) -> u64 {
    let mut a = (low ^ high).wrapping_mul(mul);
    a ^= a >> 47;
    let mut b = (high ^ a).wrapping_mul(mul);
    b ^= b >> 47;
    b.wrapping_mul(mul)
}

#[inline(always)]
fn city_hash_len_16(low: u64, high: u64) -> u64 {
    city_hash_len_16_mul(low, high, 0x9ddf_ea08_eb38_2d69)
}

fn city_hash_len_0_to_16(input: &[u8]) -> u64 {
    let len = input.len() as u64;
    if len >= 8 {
        let mul = CITY_K2.wrapping_add(len.wrapping_mul(2));
        let a = fetch64(input, 0).wrapping_add(CITY_K2);
        let b = fetch64(input, input.len() - 8);
        let c = b.rotate_right(37).wrapping_mul(mul).wrapping_add(a);
        let d = a.rotate_right(25).wrapping_add(b).wrapping_mul(mul);
        return city_hash_len_16_mul(c, d, mul);
    }
    if len >= 4 {
        let mul = CITY_K2.wrapping_add(len.wrapping_mul(2));
        let a = u64::from(fetch32(input, 0));
        return city_hash_len_16_mul(
            len.wrapping_add(a << 3),
            u64::from(fetch32(input, input.len() - 4)),
            mul,
        );
    }
    if len > 0 {
        let a = input[0];
        let b = input[input.len() >> 1];
        let c = input[input.len() - 1];
        let y = u32::from(a).wrapping_add(u32::from(b) << 8);
        let z = (input.len() as u32).wrapping_add(u32::from(c) << 2);
        return shift_mix(u64::from(y).wrapping_mul(CITY_K2) ^ u64::from(z).wrapping_mul(CITY_K0))
            .wrapping_mul(CITY_K2);
    }
    CITY_K2
}

fn city_hash_len_17_to_32(input: &[u8]) -> u64 {
    let len = input.len() as u64;
    let mul = CITY_K2.wrapping_add(len.wrapping_mul(2));
    let a = fetch64(input, 0).wrapping_mul(CITY_K1);
    let b = fetch64(input, 8);
    let c = fetch64(input, input.len() - 8).wrapping_mul(mul);
    let d = fetch64(input, input.len() - 16).wrapping_mul(CITY_K2);

    city_hash_len_16_mul(
        a.wrapping_add(b)
            .rotate_right(43)
            .wrapping_add(c.rotate_right(30))
            .wrapping_add(d),
        a.wrapping_add(b.wrapping_add(CITY_K2).rotate_right(18))
            .wrapping_add(c),
        mul,
    )
}

fn city_hash_len_33_to_64(input: &[u8]) -> u64 {
    let len = input.len() as u64;
    let mul = CITY_K2.wrapping_add(len.wrapping_mul(2));
    let a = fetch64(input, 0).wrapping_mul(CITY_K2);
    let b = fetch64(input, 8);
    let c = fetch64(input, input.len() - 24);
    let d = fetch64(input, input.len() - 32);
    let e = fetch64(input, 16).wrapping_mul(CITY_K2);
    let f = fetch64(input, 24).wrapping_mul(9);
    let g = fetch64(input, input.len() - 8);
    let h = fetch64(input, input.len() - 16).wrapping_mul(mul);

    let u = a
        .wrapping_add(g)
        .rotate_right(43)
        .wrapping_add(b.rotate_right(30).wrapping_add(c).wrapping_mul(9));
    let v = (a.wrapping_add(g) ^ d).wrapping_add(f).wrapping_add(1);
    let w = u
        .wrapping_add(v)
        .wrapping_mul(mul)
        .swap_bytes()
        .wrapping_add(h);
    let x = e.wrapping_add(f).rotate_right(42).wrapping_add(c);
    let y = v
        .wrapping_add(w)
        .wrapping_mul(mul)
        .swap_bytes()
        .wrapping_add(g)
        .wrapping_mul(mul);
    let z = e.wrapping_add(f).wrapping_add(c);
    let a1 = x
        .wrapping_add(z)
        .wrapping_mul(mul)
        .wrapping_add(y)
        .swap_bytes()
        .wrapping_add(b);
    let b1 = shift_mix(
        z.wrapping_add(a1)
            .wrapping_mul(mul)
            .wrapping_add(d)
            .wrapping_add(h),
    )
    .wrapping_mul(mul);
    b1.wrapping_add(x)
}

fn weak_hash_len_32_with_seeds(input: &[u8], offset: usize, a: u64, b: u64) -> (u64, u64) {
    let w = fetch64(input, offset);
    let x = fetch64(input, offset + 8);
    let y = fetch64(input, offset + 16);
    let z = fetch64(input, offset + 24);

    let mut a1 = a.wrapping_add(w);
    let mut b1 = b.wrapping_add(a1).wrapping_add(z).rotate_right(21);
    let c = a1;
    a1 = a1.wrapping_add(x).wrapping_add(y);
    b1 = b1.wrapping_add(a1.rotate_right(44));
    (a1.wrapping_add(z), b1.wrapping_add(c))
}

fn city_hash(input: &[u8]) -> u64 {
    if input.len() <= 32 {
        if input.len() <= 16 {
            return city_hash_len_0_to_16(input);
        }
        return city_hash_len_17_to_32(input);
    }
    if input.len() <= 64 {
        return city_hash_len_33_to_64(input);
    }

    let mut len = input.len() as u64;

    let mut x = fetch64(input, input.len() - 40);
    let mut y = fetch64(input, input.len() - 16).wrapping_add(fetch64(input, input.len() - 56));
    let mut z = city_hash_len_16(
        fetch64(input, input.len() - 48).wrapping_add(len),
        fetch64(input, input.len() - 24),
    );
    let mut v = weak_hash_len_32_with_seeds(input, input.len() - 64, len, z);
    let mut w = weak_hash_len_32_with_seeds(input, input.len() - 32, y.wrapping_add(CITY_K1), x);

    x = x.wrapping_mul(CITY_K1).wrapping_add(fetch64(input, 0));
    len = (len - 1) & !63u64;

    let mut offset = 0usize;
    loop {
        x = x
            .wrapping_add(y)
            .wrapping_add(v.0)
            .wrapping_add(fetch64(input, offset + 8))
            .rotate_right(37)
            .wrapping_mul(CITY_K1);
        y = y
            .wrapping_add(v.1)
            .wrapping_add(fetch64(input, offset + 48))
            .rotate_right(42)
            .wrapping_mul(CITY_K1);
        x ^= w.1;
        y = y
            .wrapping_add(v.0)
            .wrapping_add(fetch64(input, offset + 40));
        z = z.wrapping_add(w.0).rotate_right(33).wrapping_mul(CITY_K1);
        v = weak_hash_len_32_with_seeds(
            input,
            offset,
            v.1.wrapping_mul(CITY_K1),
            x.wrapping_add(w.0),
        );
        w = weak_hash_len_32_with_seeds(
            input,
            offset + 32,
            z.wrapping_add(w.1),
            y.wrapping_add(fetch64(input, offset + 16)),
        );
        std::mem::swap(&mut z, &mut x);

        offset += 64;
        len -= 64;
        if len == 0 {
            break;
        }
    }

    city_hash_len_16(
        city_hash_len_16(v.0, w.0)
            .wrapping_add(shift_mix(y).wrapping_mul(CITY_K1))
            .wrapping_add(z),
        city_hash_len_16(v.1, w.1).wrapping_add(x),
    )
}

/// `Bun.hash.cityHash64`, which is `CityHash64` with the seed folded into both
/// of `hash_with_seeds`' arguments and then through `hash128to64`.
pub fn city_hash64(input: &[u8], seed: u64) -> u64 {
    city_hash_len_16(city_hash(input).wrapping_sub(CITY_K2), seed)
}

// ---------------------------------------------------------------------------
// RapidHash
// ---------------------------------------------------------------------------

const RAPID_SECRET: [u64; 3] = [
    0x2d35_8dcc_aa6c_78a5,
    0x8bb8_4b93_962e_acc9,
    0x4b33_a62e_d433_d4a3,
];

#[inline(always)]
fn rapid_mix(a: u64, b: u64) -> u64 {
    let product = (a as u128).wrapping_mul(b as u128);
    (product as u64) ^ ((product >> 64) as u64)
}

/// `Bun.hash.rapidhash`.
pub fn rapidhash(input: &[u8], seed: u64) -> u64 {
    let sc = RAPID_SECRET;
    let len = input.len();
    let mut a: u64 = 0;
    let mut b: u64 = 0;
    let mut k = input;
    let mut state = [seed, 0, 0];

    state[0] ^= rapid_mix(seed ^ sc[0], sc[1]) ^ (len as u64);

    if len <= 16 {
        if len >= 4 {
            let d: usize = (len & 24) >> (len >> 3);
            let e = len - 4;
            a = (u64::from(read_u32(input)) << 32) | u64::from(read_u32(&k[e..]));
            b = (u64::from(read_u32(&k[d..])) << 32) | u64::from(read_u32(&k[e - d..]));
        } else if len > 0 {
            a = (u64::from(k[0]) << 56) | (u64::from(k[len >> 1]) << 32) | u64::from(k[len - 1]);
        }
    } else {
        let mut remain = len;
        if len > 48 {
            state[1] = state[0];
            state[2] = state[0];
            while remain >= 96 {
                for i in 0..6usize {
                    let m1 = read_u64_le(&k[8 * i * 2..]);
                    let m2 = read_u64_le(&k[8 * (i * 2 + 1)..]);
                    state[i % 3] = rapid_mix(m1 ^ sc[i % 3], m2 ^ state[i % 3]);
                }
                k = &k[96..];
                remain -= 96;
            }
            if remain >= 48 {
                for i in 0..3usize {
                    let m1 = read_u64_le(&k[8 * i * 2..]);
                    let m2 = read_u64_le(&k[8 * (i * 2 + 1)..]);
                    state[i] = rapid_mix(m1 ^ sc[i], m2 ^ state[i]);
                }
                k = &k[48..];
                remain -= 48;
            }
            state[0] ^= state[1] ^ state[2];
        }

        if remain > 16 {
            state[0] = rapid_mix(
                read_u64_le(k) ^ sc[2],
                read_u64_le(&k[8..]) ^ state[0] ^ sc[1],
            );
            if remain > 32 {
                state[0] = rapid_mix(
                    read_u64_le(&k[16..]) ^ sc[2],
                    read_u64_le(&k[24..]) ^ state[0],
                );
            }
        }

        a = read_u64_le(&input[len - 16..]);
        b = read_u64_le(&input[len - 8..]);
    }

    a ^= sc[1];
    b ^= state[0];
    let product = (a as u128).wrapping_mul(b as u128);
    a = product as u64;
    b = (product >> 64) as u64;
    rapid_mix(a ^ sc[0] ^ (len as u64), b ^ sc[1])
}

#[inline(always)]
fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Values measured from `bun 1.4.4`. The first column of each pair is
    /// `hash("abc")` and the second `hash("")`, both with seed 0.
    #[test]
    fn matches_measured_bun_values() {
        assert_eq!(adler32(b"abc"), 38_600_999);
        assert_eq!(adler32(b""), 1);

        assert_eq!(murmur32v2(b"abc", 0), 324_500_635);
        assert_eq!(murmur32v2(b"", 0), 0);
        assert_eq!(murmur32v3(b"abc", 0), 3_017_643_002);
        assert_eq!(murmur32v3(b"", 0), 0);
        assert_eq!(murmur64v2(b"abc", 0), 11_297_775_770_902_552_315);
        assert_eq!(murmur64v2(b"", 0), 0);

        assert_eq!(xxhash32(b"abc", 0), 852_579_327);
        assert_eq!(xxhash32(b"", 0), 46_947_589);
        assert_eq!(xxhash64(b"abc", 0), 4_952_883_123_889_572_249);
        assert_eq!(xxhash64(b"", 0), 17_241_709_254_077_376_921);
        assert_eq!(xxhash3(b"abc", 0), 8_696_274_497_037_089_104);
        assert_eq!(xxhash3(b"", 0), 3_244_421_341_483_603_138);

        assert_eq!(city_hash32(b"abc"), 795_041_479);
        assert_eq!(city_hash32(b""), 3_696_677_242);
        assert_eq!(city_hash64(b"abc", 0), 6_234_256_295_332_240_817);
        assert_eq!(city_hash64(b"", 0), 0);

        assert_eq!(rapidhash(b"abc", 0), 8_246_329_693_904_217_010);
        assert_eq!(rapidhash(b"", 0), 10_602_188_539_874_428_322);
    }
}
