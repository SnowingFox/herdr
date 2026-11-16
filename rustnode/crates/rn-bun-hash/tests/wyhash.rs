//! `Bun.hash` against 504 vectors recorded from `bun 1.4.4`.
//!
//! The fixture is a dense sweep — every length from 0 to 250 bytes, each hashed
//! with seed 0 and with a non-zero seed — plus lengths above the 240-byte
//! midsize cutoff, up to 100 000 bytes, so the multi-block stripe loop is
//! exercised rather than inferred.
//!
//! A length sweep rather than a handful of strings is the point. wyhash's
//! branches on the input length at 16, 48 and 240 bytes and treats a 48-byte
//! boundary differently from the streaming path; three sample strings would pass
//! against a wrong variant. The vectors were recorded *from the oracle*, never
//! from this crate, so they cannot drift to whatever this code happens to
//! produce.

use rn_bun_hash::wyhash::hash;

#[test]
fn wyhash_matches_every_recorded_vector() {
    let fixture = include_str!("fixtures/wyhash-vectors.txt");

    let mut compared = 0usize;
    for (index, line) in fixture.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let len: usize = parts
            .next()
            .and_then(|text| text.parse().ok())
            .unwrap_or_else(|| panic!("line {}: no length", index + 1));
        let seed: u64 = parts
            .next()
            .and_then(|text| text.parse().ok())
            .unwrap_or_else(|| panic!("line {}: no seed", index + 1));
        let expected: u64 = parts
            .next()
            .and_then(|text| text.parse().ok())
            .unwrap_or_else(|| panic!("line {}: no digest", index + 1));

        let input: Vec<u8> = (0..len).map(|i| ((i * 37 + 11) & 0xff) as u8).collect();
        assert_eq!(
            hash(seed, &input),
            expected,
            "wyhash of {len} bytes with seed {seed}"
        );
        compared += 1;
    }

    // A fixture that silently lost its body would make every assertion above
    // vacuous. 251 lengths × 2 seeds (0..=250) + 7 large lengths × 2 seeds.
    assert_eq!(compared, 516, "fixture shape changed");
}
