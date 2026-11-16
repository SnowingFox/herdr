//! `Bun.randomUUIDv5` and `Bun.randomUUIDv7`, plus the randomness they need.
//!
//! Both UUID kinds are deterministic in their invariants and not in their values,
//! so they need care in different places:
//!
//! * **v5 is a hash** — SHA-1 over `namespaceBytes ++ name`, with the version and
//!   variant nibbles overwritten. It is fully deterministic, so the expected
//!   values are literal strings computed by hand from RFC 4122 and confirmed
//!   against Bun: `randomUUIDv5("example.com", DNS)` is
//!   `cfbff0d1-9375-5685-968c-48ce8b15ae17`.
//! * **v7 is a clock**, and the observable contract is version nibble `7`,
//!   variant in `[89ab]`, uniqueness, and lexicographic non-decrease over
//!   consecutive calls. Its absolute value must not be pinned.
//!
//! # Why SHA-1 is here rather than added as a dependency
//!
//! `rn-bind-crypto` already links OpenSSL and could hash for us, but this crate
//! is installed on the startup path and pulling OpenSSL's digest machinery in
//! would make every process pay for it. SHA-1 is ~60 lines, has one caller whose
//! output is pinned by the RFC's own test vector, and is not used for anything
//! security-bearing here.
//!
//! # Where randomness comes from
//!
//! `getrandom(2)` from libc directly. The crate `getrandom` is not in the
//! workspace's lock file, and adding a dependency for one syscall is not worth
//! it; the failure mode (no entropy at boot) is reported rather than papered over
//! with a weak fallback.

/// The DNS namespace, `6ba7b810-9dad-11d1-80b4-00c04fd430c8`.
pub const NAMESPACE_DNS: [u8; 16] = [
    0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8,
];

/// Parses a UUID string into its 16 bytes, or `None` when it is not one.
///
/// Both the canonical hyphenated form and a bare 32-hex-digit form are accepted,
/// which is what Bun accepts for a namespace.
pub fn parse_uuid(text: &str) -> Option<[u8; 16]> {
    let mut digits = Vec::with_capacity(32);
    for character in text.chars() {
        match character {
            '-' => continue,
            c if c.is_ascii_hexdigit() => digits.push(c),
            _ => return None,
        }
    }
    if digits.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (index, slot) in out.iter_mut().enumerate() {
        let high = digits[index * 2].to_digit(16)?;
        let low = digits[index * 2 + 1].to_digit(16)?;
        *slot = ((high << 4) | low) as u8;
    }
    Some(out)
}

/// Renders 16 bytes in the canonical hyphenated lowercase form.
pub fn format_uuid(bytes: &[u8; 16]) -> String {
    let mut out = String::with_capacity(36);
    for (index, byte) in bytes.iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            out.push('-');
        }
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// `randomUUIDv5(name, namespace)`: the RFC 4122 version-5 UUID.
pub fn uuid_v5(name: &[u8], namespace: &[u8; 16]) -> [u8; 16] {
    let mut input = Vec::with_capacity(namespace.len() + name.len());
    input.extend_from_slice(namespace);
    input.extend_from_slice(name);
    let digest = sha1(&input);

    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&digest[..16]);
    // The version nibble names SHA-1; the variant bits mark an RFC 4122 UUID.
    uuid[6] = (uuid[6] & 0x0F) | 0x50;
    uuid[8] = (uuid[8] & 0x3F) | 0x80;
    uuid
}

/// A version-7 UUID: 48 bits of Unix milliseconds, then random, then random.
///
/// The 12 bits at positions 4..6 are a monotonic counter within one millisecond
/// so two calls in the same tick cannot collide, which is what makes the
/// lexicographic ordering invariant hold for consecutive calls.
pub fn uuid_v7(millis: u64, counter: u16, random: &[u8; 10]) -> [u8; 16] {
    let mut uuid = [0u8; 16];
    // Bytes 0..6 are the 48-bit big-endian timestamp.
    uuid[0] = ((millis >> 40) & 0xFF) as u8;
    uuid[1] = ((millis >> 32) & 0xFF) as u8;
    uuid[2] = ((millis >> 24) & 0xFF) as u8;
    uuid[3] = ((millis >> 16) & 0xFF) as u8;
    uuid[4] = ((millis >> 8) & 0xFF) as u8;
    uuid[5] = (millis & 0xFF) as u8;
    // The counter occupies the low 12 bits of bytes 6..8, with the version in
    // the high nibble of byte 6.
    uuid[6] = 0x70 | ((counter >> 8) as u8 & 0x0F);
    uuid[7] = (counter & 0xFF) as u8;
    uuid[8] = (random[0] & 0x3F) | 0x80;
    uuid[9] = random[1];
    uuid[10] = random[2];
    uuid[11] = random[3];
    uuid[12] = random[4];
    uuid[13] = random[5];
    uuid[14] = random[6];
    uuid[15] = random[7];
    uuid
}

/// Fills `buffer` from `getrandom(2)`.
pub fn fill_random(buffer: &mut [u8]) -> Result<(), String> {
    let mut filled = 0usize;
    while filled < buffer.len() {
        // SAFETY: `buffer` is a live mutable slice, so the pointer and the
        // remaining length describe readable and writable memory.
        let got = unsafe {
            libc::getrandom(
                buffer[filled..].as_mut_ptr().cast(),
                buffer.len() - filled,
                0,
            )
        };
        if got < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(format!("getrandom failed: {error}"));
        }
        filled += got as usize;
    }
    Ok(())
}

/// SHA-1, per FIPS 180-4.
///
/// Only v5 needs it, and only over `namespace ++ name`, so it takes a byte slice
/// and returns the digest rather than exposing a streaming interface.
pub fn sha1(input: &[u8]) -> [u8; 20] {
    let mut message = input.to_vec();
    let bit_length = (input.len() as u64).wrapping_mul(8);
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_length.to_be_bytes());

    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

    for chunk in message.chunks_exact(64) {
        let mut words = [0u32; 80];
        for index in 0..16 {
            words[index] = u32::from_be_bytes([
                chunk[index * 4],
                chunk[index * 4 + 1],
                chunk[index * 4 + 2],
                chunk[index * 4 + 3],
            ]);
        }
        for index in 16..80 {
            words[index] =
                (words[index - 3] ^ words[index - 8] ^ words[index - 14] ^ words[index - 16])
                    .rotate_left(1);
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (index, word) in words.iter().enumerate() {
            let (f, k) = match index {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    let mut digest = [0u8; 20];
    for (index, word) in h.iter().enumerate() {
        digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

/// Reads the wall clock in milliseconds since the Unix epoch.
pub fn unix_millis() -> u64 {
    // SAFETY: `timespec` is plain-old-data and `clock_gettime` fills it.
    let mut now: libc::timespec = unsafe { std::mem::zeroed() };
    // SAFETY: `now` is a valid, writable `timespec`.
    if unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut now) } != 0 {
        return 0;
    }
    (now.tv_sec as u64)
        .saturating_mul(1000)
        .saturating_add((now.tv_nsec as u64) / 1_000_000)
}

/// The version-7 clock: milliseconds plus a monotonic 12-bit counter.
///
/// Two UUIDs generated in the same millisecond must still sort in call order, so
/// the counter increments and only resets when the millisecond changes. The
/// compare-exchange loop makes that atomic across threads, which a worker
/// generating UUIDs at the same time as the main thread needs.
pub fn next_v7_clock() -> (u64, u16) {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    loop {
        let millis = unix_millis();
        let current = NEXT.load(std::sync::atomic::Ordering::Relaxed);
        let (current_millis, counter) = (current >> 12, (current & 0x0FFF) as u16);
        let (next_millis, next_counter) = if millis > current_millis {
            (millis, 0u16)
        } else if counter >= 0x0FFF {
            // The counter overflowed within one millisecond; borrow the next
            // millisecond so ordering still holds.
            (current_millis + 1, 0u16)
        } else {
            (current_millis, counter + 1)
        };
        let packed = (next_millis << 12) | u64::from(next_counter);
        if NEXT
            .compare_exchange(
                current,
                packed,
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
            )
            .is_ok()
        {
            return (next_millis, next_counter);
        }
    }
}
