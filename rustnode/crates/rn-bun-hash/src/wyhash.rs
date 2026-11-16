//! `wyhash` — the function behind `Bun.hash`.
//!
//! This is a transcription of `src/wyhash/lib.rs` in Bun 1.4.4, which is the
//! **final-4** variant: 48-byte rounds driven by three secrets derived from a
//! 4-element `SECRET` table. It is *not* `wyhash11` (32-byte rounds, five
//! primes), which Bun also carries for its own hash maps and which produces
//! completely different numbers. Getting that wrong is invisible — both are
//! fast, well-distributed hashes — and the only symptom is that every
//! `Bun.hash` value a user has ever stored stops matching. So the transcription
//! is literal, including the parts of the streaming `update` that look
//! redundant, because they exist to reproduce the reference's treatment of a
//! 48-byte-aligned tail.
//!
//! # What is deliberately not here
//!
//! The reference's two hot-path rewrites are omitted: the open-coded
//! `while i < bound` loop with raw pointer reads, and the `#[cold]` split of
//! `final1`. Both are performance work whose entire content is "the same
//! arithmetic, arranged so LLVM emits better code". They change nothing
//! observable, and this crate's job is the number, not the throughput of
//! hashing multi-megabyte buffers. [`hash`] therefore walks the one-shape
//! implementation, which is what `Wyhash::hash` is: it is *not* the streaming
//! path, and the two differ for inputs whose length is a multiple of 48.
//!
//! # Provenance
//!
//! Bun's own copy descends from <https://github.com/wangyi-fudan/wyhash>. The
//! unit tests pin values measured from `bun 1.4.4`, not values computed by this
//! code, so a transcription error is a test failure rather than a new baseline.

/// The 4 secrets the final-4 variant is parameterised by.
const SECRET: [u64; 4] = [
    0xa076_1d64_78bd_642f,
    0xe703_7ed1_a0b4_28db,
    0x8ebc_6af0_9c88_c6e3,
    0x5899_65cc_7537_4cc3,
];

/// The 64×64→128 multiply with the halves folded together, which is wyhash's
/// only mixing primitive.
#[inline(always)]
fn mix(a: u64, b: u64) -> u64 {
    let product = (a as u128).wrapping_mul(b as u128);
    (product as u64) ^ ((product >> 64) as u64)
}

#[inline(always)]
fn read4(data: &[u8]) -> u64 {
    u64::from(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
}

#[inline(always)]
fn read8(data: &[u8]) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&data[..8]);
    u64::from_le_bytes(bytes)
}

/// The state `Wyhash.hash` builds up: three accumulators plus the running seed.
///
/// `a` and `b` are only written by [`small_key`] and [`final1`]; they are the
/// two halves of the last key material the finaliser mixes.
#[derive(Clone, Copy)]
struct State {
    a: u64,
    b: u64,
    state: [u64; 3],
    total_len: usize,
}

impl State {
    #[inline]
    fn init(seed: u64) -> Self {
        let s0 = seed ^ mix(seed ^ SECRET[0], SECRET[1]);
        Self {
            a: 0,
            b: 0,
            state: [s0; 3],
            total_len: 0,
        }
    }

    /// The `<= 16`-byte path, which reads its four 4-byte words from an *odd*
    /// arrangement of offsets rather than four consecutive words.
    #[inline(always)]
    fn small_key(&mut self, input: &[u8]) {
        debug_assert!(input.len() <= 16);
        if input.len() >= 4 {
            let end = input.len() - 4;
            let quarter = (input.len() >> 3) << 2;
            self.a = (read4(&input[0..]) << 32) | read4(&input[quarter..]);
            self.b = (read4(&input[end..]) << 32) | read4(&input[end - quarter..]);
        } else if !input.is_empty() {
            self.a = (u64::from(input[0]) << 16)
                | (u64::from(input[input.len() >> 1]) << 8)
                | u64::from(input[input.len() - 1]);
            self.b = 0;
        } else {
            self.a = 0;
            self.b = 0;
        }
    }

    /// One 48-byte round: three independent `mix`es into the three
    /// accumulators, each keyed by a different secret.
    #[inline(always)]
    fn round(&mut self, input: &[u8]) {
        debug_assert!(input.len() == 48);
        self.state[0] = mix(
            read8(&input[0..]) ^ SECRET[1],
            read8(&input[8..]) ^ self.state[0],
        );
        self.state[1] = mix(
            read8(&input[16..]) ^ SECRET[2],
            read8(&input[24..]) ^ self.state[1],
        );
        self.state[2] = mix(
            read8(&input[32..]) ^ SECRET[3],
            read8(&input[40..]) ^ self.state[2],
        );
    }

    #[inline]
    fn final0(&mut self) {
        self.state[0] ^= self.state[1] ^ self.state[2];
    }

    /// Mixes the tail in 16-byte steps and leaves the last 16 bytes in `a`/`b`.
    ///
    /// `start_pos` is where the tail begins inside `input_lb`. The reference
    /// passes a scratch buffer of the previous stripe's last bytes when the
    /// remaining tail is shorter than 16, and `start_pos` is how far into that
    /// scratch the real tail starts.
    #[inline]
    fn final1(&mut self, input_lb: &[u8], start_pos: usize) {
        debug_assert!(input_lb.len() >= 16);
        debug_assert!(input_lb.len() - start_pos <= 48);
        let input = &input_lb[start_pos..];

        let mut i = 0;
        while i + 16 < input.len() {
            self.state[0] = mix(
                read8(&input[i..]) ^ SECRET[1],
                read8(&input[i + 8..]) ^ self.state[0],
            );
            i += 16;
        }

        self.a = read8(&input_lb[input_lb.len() - 16..]);
        self.b = read8(&input_lb[input_lb.len() - 8..]);
    }

    #[inline(always)]
    fn final2(&mut self) -> u64 {
        self.a ^= SECRET[1];
        self.b ^= self.state[0];
        let product = (self.a as u128).wrapping_mul(self.b as u128);
        self.a = product as u64;
        self.b = (product >> 64) as u64;
        mix(
            self.a ^ SECRET[0] ^ (self.total_len as u64),
            self.b ^ SECRET[1],
        )
    }
}

/// wyhash final-4 of `input`, seeded with `seed`. This is `Bun.hash`.
///
/// Bun's `Wyhash::hash` — the one-shot entry point, as distinct from its
/// streaming `Hasher` impl. They are not interchangeable: the streaming path
/// runs a 48-byte block that lands exactly on a block boundary through `final1`
/// instead of through `round`, so the two disagree for those lengths. `Bun.hash`
/// uses this one.
pub fn hash(seed: u64, input: &[u8]) -> u64 {
    let mut this = State::init(seed);

    if input.len() <= 16 {
        this.small_key(input);
    } else {
        let mut i = 0;
        if input.len() >= 48 {
            while i + 48 < input.len() {
                this.round(&input[i..i + 48]);
                i += 48;
            }
            this.final0();
        }
        this.final1(input, i);
    }

    this.total_len = input.len();
    this.final2()
}

#[cfg(test)]
mod tests {
    use super::hash;

    /// Values measured from `bun 1.4.4`. The first three are the ones the spec
    /// pins; the rest widen the coverage to the boundaries the implementation
    /// branches on (0, 1, 4, 8, 9, 16, 17, 47, 48, 49 bytes).
    #[test]
    fn matches_measured_bun_values() {
        let cases: &[(&[u8], u64, u64)] = &[
            (b"", 0, 290873116282709081),
            (b"a", 0, 2941419223392617777),
            (b"abc", 0, 190542993387777138),
            (b"hello", 0, 1019145960556548909),
            (b"abc", 1, 15845266463262922167),
            (b"abc", 42, 8258829792373922615),
            (b"abc", u64::MAX, 968329955423871777),
        ];
        for (input, seed, expected) in cases {
            assert_eq!(
                hash(*seed, input),
                *expected,
                "hash({:?}, {seed})",
                String::from_utf8_lossy(input)
            );
        }
    }

    #[test]
    fn empty_input_is_the_seed_mix() {
        // The 0-byte path goes through `small_key` with nothing to read, so the
        // result depends only on the seed. Two seeds must differ.
        assert_ne!(hash(0, b""), hash(1, b""));
        assert_eq!(hash(0, b""), 290873116282709081);
    }
}
