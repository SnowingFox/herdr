//! The decoder state that lives in the JavaScript `Buffer.alloc(kSize)`.
//!
//! `src/string_decoder.h` defines seven `u8` fields; this module is that struct
//! and the two operations `src/string_decoder.cc` performs on it. Keeping the
//! state byte-compatible matters because the JavaScript reads and writes it
//! directly:
//!
//! ```js
//! this[kNativeDecoder][kEncodingField] = encodingsMap[this.encoding];
//! if (this[kNativeDecoder][kBufferedBytes] > 0) return ret + flush(...);
//! get lastChar() { return state.subarray(kIncompleteCharactersStart,
//!                                      kIncompleteCharactersEnd); }
//! ```
//!
//! The split between *deciding what bytes to emit* ([`State::decode`]) and
//! *turning bytes into a V8 string* is deliberate: everything that decides
//! retention is testable without an isolate, and the string construction is the
//! one part that must go through V8 to reproduce its replacement-character
//! behaviour.

use std::ops::Range;

/// `kIncompleteCharactersStart`.
pub const INCOMPLETE_START: i32 = 0;
/// `kIncompleteCharactersEnd`. Also the width of the incomplete buffer, and the
/// most bytes that can ever be retained: a four-byte UTF-8 character missing
/// one byte, or two UTF-16LE bytes plus the high surrogate they complete.
pub const INCOMPLETE_END: i32 = 4;
/// `kMissingBytes`.
pub const MISSING_BYTES: i32 = 4;
/// `kBufferedBytes`.
pub const BUFFERED_BYTES: i32 = 5;
/// `kEncodingField`.
pub const ENCODING_FIELD: i32 = 6;
/// `kNumFields`.
pub const FIELD_COUNT: usize = 7;

/// Width of the incomplete-character buffer, from `kIncompleteCharactersEnd`.
pub const CAPACITY: usize = INCOMPLETE_END as usize;

/// `enum encoding` from `src/node.h`.
///
/// The discriminants are the index into the `encodings` array, because
/// `lib/internal/util.js` builds its `encodingsMap` from that array and the
/// decoder stores the resulting index in `kEncodingField`. `BINARY` is an alias
/// of `LATIN1` and so never appears as its own entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Encoding {
    Ascii = 0,
    Utf8 = 1,
    Base64 = 2,
    Ucs2 = 3,
    Latin1 = 4,
    Hex = 5,
    Buffer = 6,
    Base64Url = 7,
}

impl Encoding {
    /// The `enum encoding` value, as stored in `kEncodingField`.
    #[must_use]
    pub fn field(self) -> u8 {
        self as u8
    }

    /// Reads a stored field. `None` for a byte that is not an encoding.
    #[must_use]
    pub fn from_field(field: u8) -> Option<Self> {
        Some(match field {
            0 => Encoding::Ascii,
            1 => Encoding::Utf8,
            2 => Encoding::Base64,
            3 => Encoding::Ucs2,
            4 => Encoding::Latin1,
            5 => Encoding::Hex,
            6 => Encoding::Buffer,
            7 => Encoding::Base64Url,
            _ => return None,
        })
    }

    /// Whether `decode` retains a trailing partial character for this encoding.
    ///
    /// `DecodeData`'s first branch covers UTF-8, UTF-16LE and both base64
    /// variants; `ascii`, `hex` and `latin1` map one input byte to one output
    /// unit and never need to wait for more.
    #[must_use]
    pub fn retains(self) -> bool {
        matches!(
            self,
            Encoding::Utf8 | Encoding::Ucs2 | Encoding::Base64 | Encoding::Base64Url
        )
    }
}

/// What one `decode` call should emit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded {
    /// The encoding both parts are to be decoded with.
    pub encoding: Encoding,
    /// Bytes completed from the previous chunk. Empty when nothing was pending,
    /// or when the pending character is still incomplete.
    pub prepend: Vec<u8>,
    /// The part of the chunk that forms this call's body.
    pub body: Range<usize>,
}

/// What a `flush` call should emit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flushed {
    /// The encoding the bytes are to be decoded with.
    pub encoding: Encoding,
    /// The retained bytes. Empty means the caller gets the empty string.
    pub bytes: Vec<u8>,
}

/// The seven bytes `lib/string_decoder.js` allocates.
///
/// `#[repr(C)]` with only `u8` fields, so the layout is exactly the field order
/// in `StringDecoder::Fields` with no padding; [`SIZE`] is checked against
/// `kNumFields` in the tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct State {
    incomplete: [u8; CAPACITY],
    missing: u8,
    buffered: u8,
    encoding: u8,
}

/// `sizeof(StringDecoder)`, which Node exports as `kSize`.
pub const SIZE: usize = std::mem::size_of::<State>();

impl Default for State {
    fn default() -> Self {
        Self::new(Encoding::Utf8)
    }
}

impl State {
    /// A fresh, empty state for `encoding`.
    ///
    /// Node's `StringDecoder()` constructor writes `BUFFER` into the encoding
    /// field, but the JavaScript overwrites it immediately with
    /// `encodingsMap[normalizeEncoding(...)]`, so the initial value is not
    /// observable through the public API.
    #[must_use]
    pub fn new(encoding: Encoding) -> Self {
        Self {
            incomplete: [0; CAPACITY],
            missing: 0,
            buffered: 0,
            encoding: encoding.field(),
        }
    }

    /// The encoding this state decodes with, or `None` if the field is corrupt.
    #[must_use]
    pub fn encoding(&self) -> Option<Encoding> {
        Encoding::from_field(self.encoding)
    }

    /// `kMissingBytes`: how many bytes the retained character still needs.
    #[must_use]
    pub fn missing_bytes(&self) -> u8 {
        self.missing
    }

    /// `kBufferedBytes`: how many bytes are retained.
    #[must_use]
    pub fn buffered_bytes(&self) -> u8 {
        self.buffered
    }

    /// The retained bytes, i.e. what `lastChar` exposes.
    #[must_use]
    pub fn last_char(&self) -> &[u8] {
        &self.incomplete[..self.buffered as usize]
    }

    /// `StringDecoder::DecodeData`: decides what to emit and what to retain.
    ///
    /// Returns `None` when the state is not usable — an unknown encoding, or
    /// counters that would write past the four-byte buffer. Node `CHECK`s those
    /// and aborts the process; a binding crate must not abort on JavaScript
    /// input, so the caller turns this into a `TypeError` instead.
    pub fn decode(&mut self, chunk: &[u8]) -> Option<Decoded> {
        let encoding = self.encoding()?;
        if !encoding.retains() {
            // `DecodeData`'s `else` branch: ASCII, HEX and LATIN1 map straight
            // through, and BUFFER is unreachable from the public constructor
            // (see the crate docs). BUFFER is rejected rather than encoded.
            if encoding == Encoding::Buffer {
                return None;
            }
            return Some(Decoded {
                encoding,
                prepend: Vec::new(),
                body: 0..chunk.len(),
            });
        }

        let mut offset = 0usize;
        let mut prepend = Vec::new();

        if self.missing > 0 {
            // `CHECK_LE(MissingBytes() + BufferedBytes(), kIncompleteCharactersEnd)`.
            if usize::from(self.missing) + usize::from(self.buffered) > CAPACITY {
                return None;
            }

            if encoding == Encoding::Utf8 {
                // Node: if a byte that should have been a continuation byte is
                // not one, stop the pending character here and let the
                // unexpected byte begin a new one. The bytes already consumed
                // are still completed and emitted, so the result is a
                // replacement character followed by the new character.
                let limit = chunk.len().min(usize::from(self.missing));
                for index in 0..limit {
                    if chunk[index] & 0xC0 != 0x80 {
                        self.missing = 0;
                        self.append(&chunk[..index])?;
                        offset = index;
                        break;
                    }
                }
            }

            let found = (chunk.len() - offset).min(usize::from(self.missing));
            self.append(&chunk[offset..offset + found])?;
            offset += found;
            self.missing = self.missing.saturating_sub(found as u8);

            if self.missing == 0 {
                // The character is whole: emit it ahead of this chunk's body.
                // It is encoded on its own, which is what makes a completed
                // base64 group come out unpadded and then stop.
                prepend = self.last_char().to_vec();
                self.buffered = 0;
            }
        }

        if chunk.len() == offset {
            // The chunk only finished the previous character, or there was
            // nothing new at all. `prepend` alone is the result.
            return Some(Decoded {
                encoding,
                prepend,
                body: offset..offset,
            });
        }

        // Reaching here means no character is pending any more, which is what
        // `DecodeData` asserts before looking for a new split point.
        self.missing = 0;
        self.buffered = 0;

        let data = &chunk[offset..];
        let nread = data.len();

        if encoding == Encoding::Utf8 && data[nread - 1] & 0x80 != 0 {
            self.scan_utf8_tail(data)?;
        } else if encoding == Encoding::Ucs2 {
            if nread % 2 == 1 {
                // Half a code unit; the low byte is retained on its own.
                self.buffered = 1;
                self.missing = 1;
            } else if data[nread - 1] & 0xFC == 0xD8 {
                // The last code unit is a high surrogate, so the pair may be
                // completed by the next chunk. Little-endian, so the high byte
                // of the unit is the last byte.
                self.buffered = 2;
                self.missing = 2;
            }
        } else if matches!(encoding, Encoding::Base64 | Encoding::Base64Url) {
            // Base64 needs the input length to be a multiple of three, because
            // every three bytes make one unpadded four-character group.
            self.buffered = (nread % 3) as u8;
            if self.buffered > 0 {
                self.missing = 3 - self.buffered;
            }
        }

        let body_end = if self.buffered > 0 {
            let body_length = nread - usize::from(self.buffered);
            self.store(&data[body_length..])?;
            offset + body_length
        } else {
            offset + nread
        };

        Some(Decoded {
            encoding,
            prepend,
            body: offset..body_end,
        })
    }

    /// The UTF-8 half of `DecodeData`: walk back from the end of the chunk to
    /// see whether its last bytes begin a character that this chunk does not
    /// finish.
    ///
    /// Two cases deliberately retain nothing:
    ///
    /// * More than three continuation bytes in a row, or a chunk that starts
    ///   with one: there is no lead byte to complete, so this is invalid UTF-8
    ///   and V8's own decoder should report it.
    /// * A "lead" byte that promises a five- or six-byte character, which UTF-8
    ///   cannot represent and JavaScript strings cannot hold.
    fn scan_utf8_tail(&mut self, data: &[u8]) -> Option<()> {
        let mut index = data.len() - 1;
        loop {
            self.buffered += 1;
            if data[index] & 0xC0 == 0x80 {
                if self.buffered >= CAPACITY as u8 || index == 0 {
                    self.buffered = 0;
                    return Some(());
                }
                index -= 1;
                continue;
            }

            let width = if data[index] & 0xE0 == 0xC0 {
                2
            } else if data[index] & 0xF0 == 0xE0 {
                3
            } else if data[index] & 0xF8 == 0xF0 {
                4
            } else {
                self.buffered = 0;
                return Some(());
            };
            self.missing = width;
            if self.buffered >= self.missing {
                // As many trailing bytes as the lead byte promised, or more:
                // nothing to wait for, and in the "more" case the sequence is
                // invalid anyway.
                self.missing = 0;
                self.buffered = 0;
            }
            self.missing = self.missing.saturating_sub(self.buffered);
            return Some(());
        }
    }

    /// `StringDecoder::FlushData`: emit the retained bytes, then forget them.
    ///
    /// For `utf16le`, a single retained byte is the low half of a code unit with
    /// no partner; Node drops it rather than emitting a replacement character,
    /// and this does the same.
    pub fn flush(&mut self) -> Option<Flushed> {
        let encoding = self.encoding()?;

        if encoding == Encoding::Ucs2 && self.buffered % 2 == 1 {
            self.missing -= 1;
            self.buffered -= 1;
        }

        if self.buffered == 0 {
            // `FlushData` clears both counters only on the path that emits, but
            // they are already zero here, so the state is equivalent.
            return Some(Flushed {
                encoding,
                bytes: Vec::new(),
            });
        }

        let bytes = self.last_char().to_vec();
        self.missing = 0;
        self.buffered = 0;
        Some(Flushed { encoding, bytes })
    }

    /// Appends to the retained bytes without replacing them.
    fn append(&mut self, bytes: &[u8]) -> Option<()> {
        let start = usize::from(self.buffered);
        let end = start.checked_add(bytes.len())?;
        if end > CAPACITY {
            return None;
        }
        self.incomplete[start..end].copy_from_slice(bytes);
        self.buffered = end as u8;
        Some(())
    }

    /// Replaces the retained bytes with the tail of a chunk.
    fn store(&mut self, bytes: &[u8]) -> Option<()> {
        if bytes.len() > CAPACITY {
            return None;
        }
        self.incomplete[..bytes.len()].copy_from_slice(bytes);
        self.buffered = bytes.len() as u8;
        Some(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drives a decoder the way `StringDecoder.prototype.write` does: decode,
    /// then encode, then concatenate.
    fn write(state: &mut State, chunk: &[u8]) -> String {
        let decoded = state.decode(chunk).expect("decode succeeds");
        let mut out = String::new();
        if !decoded.prepend.is_empty() {
            out.push_str(&encode(&decoded.encoding, &decoded.prepend));
        }
        out.push_str(&encode(&decoded.encoding, &chunk[decoded.body]));
        out
    }

    /// `StringDecoder.prototype.end`: flush only when something is retained,
    /// which is the condition `lib/string_decoder.js` checks.
    fn end(state: &mut State) -> String {
        if state.buffered_bytes() == 0 {
            return String::new();
        }
        let flushed = state.flush().expect("flush succeeds");
        encode(&flushed.encoding, &flushed.bytes)
    }

    /// The Rust stand-in for V8's decoder, shared with `encode`'s own tests.
    fn encode(encoding: &Encoding, bytes: &[u8]) -> String {
        crate::encode::text(*encoding, bytes)
    }

    #[test]
    fn layout_is_seven_bytes_in_field_order() {
        assert_eq!(SIZE, FIELD_COUNT);
        assert_eq!(SIZE, 7);
        let state = State::new(Encoding::Ucs2);
        let bytes = state_bytes(&state);
        assert_eq!(bytes, [0, 0, 0, 0, 0, 0, Encoding::Ucs2.field()]);
    }

    fn state_bytes(state: &State) -> [u8; SIZE] {
        // SAFETY: `State` is `#[repr(C)]` with `u8` fields only, so every bit
        // pattern is valid and all seven bytes are initialised.
        unsafe { *(state as *const State).cast::<[u8; SIZE]>() }
    }

    #[test]
    fn split_four_byte_emoji_is_retained_then_completed() {
        let mut state = State::new(Encoding::Utf8);
        let emoji = "😀".as_bytes();
        assert_eq!(emoji, [0xF0, 0x9F, 0x98, 0x80]);

        assert_eq!(write(&mut state, &emoji[..2]), "");
        assert_eq!(state.buffered_bytes(), 2);
        assert_eq!(state.missing_bytes(), 2);
        assert_eq!(state.last_char(), &emoji[..2]);

        assert_eq!(write(&mut state, &emoji[2..]), "😀");
        assert_eq!(state.buffered_bytes(), 0);
        assert_eq!(state.missing_bytes(), 0);
        assert_eq!(end(&mut state), "");
    }

    #[test]
    fn a_lone_trailing_partial_byte_becomes_one_replacement_character() {
        let mut state = State::new(Encoding::Utf8);
        assert_eq!(write(&mut state, &[0x61, 0xE2]), "a");
        assert_eq!(state.missing_bytes(), 2);
        assert_eq!(state.last_char(), &[0xE2]);
        assert_eq!(end(&mut state), "\u{FFFD}");
        // Flush leaves the decoder reusable.
        assert_eq!(state.buffered_bytes(), 0);
        assert_eq!(write(&mut state, b"ok"), "ok");
    }

    #[test]
    fn byte_by_byte_emoji_stream_matches_node() {
        // Node's observed writes for "a😀b😀c", one byte at a time.
        let mut state = State::new(Encoding::Utf8);
        let text = "a😀b😀c";
        let expected = ["a", "", "", "", "😀", "b", "", "", "", "😀", "c"];
        let mut actual = Vec::new();
        for byte in text.as_bytes() {
            actual.push(write(&mut state, &[*byte]));
        }
        assert_eq!(actual, expected);
        assert_eq!(end(&mut state), "");
    }

    #[test]
    fn a_non_continuation_byte_aborts_the_pending_character() {
        // F0 9F is a valid prefix, then 0x41 is not a continuation byte. Node
        // emits one replacement character for the aborted pair, then the "A".
        let mut state = State::new(Encoding::Utf8);
        let emoji = "😀".as_bytes();
        assert_eq!(write(&mut state, &emoji[..2]), "");
        assert_eq!(write(&mut state, b"A"), "\u{FFFD}A");
        assert_eq!(state.buffered_bytes(), 0);
        assert_eq!(end(&mut state), "");
    }

    #[test]
    fn too_many_continuation_bytes_are_not_retained() {
        let mut state = State::new(Encoding::Utf8);
        // Five continuation bytes cannot belong to one character.
        let chunk = [0x80, 0x80, 0x80, 0x80, 0x80];
        write(&mut state, &chunk);
        assert_eq!(state.buffered_bytes(), 0);
        assert_eq!(state.missing_bytes(), 0);
    }

    #[test]
    fn utf16_le_surrogate_pair_is_split() {
        let mut state = State::new(Encoding::Ucs2);
        let emoji = "😀".encode_utf16().collect::<Vec<_>>();
        let bytes: Vec<u8> = emoji.iter().flat_map(|unit| unit.to_le_bytes()).collect();
        assert_eq!(bytes, [0x3D, 0xD8, 0x00, 0xDE]);

        assert_eq!(write(&mut state, &bytes[..2]), "");
        assert_eq!(state.buffered_bytes(), 2);
        assert_eq!(state.missing_bytes(), 2);
        assert_eq!(write(&mut state, &bytes[2..]), "😀");
        assert_eq!(end(&mut state), "");
    }

    #[test]
    fn utf16_le_odd_byte_is_dropped_by_flush() {
        let mut state = State::new(Encoding::Ucs2);
        assert_eq!(write(&mut state, &[0x41]), "");
        assert_eq!(state.buffered_bytes(), 1);
        // A single low byte has no partner; Node drops it rather than emitting
        // a replacement character.
        assert_eq!(end(&mut state), "");
        assert_eq!(state.buffered_bytes(), 0);
    }

    #[test]
    fn base64_retains_up_to_two_bytes() {
        for (length, written, flushed) in [
            (1, "", "QQ=="),
            (2, "", "QUI="),
            (3, "QUJD", ""),
            (4, "QUJD", "RA=="),
            (5, "QUJD", "REU="),
        ] {
            let chunk: Vec<u8> = (0..length).map(|index| 0x41 + index as u8).collect();
            let mut state = State::new(Encoding::Base64);
            assert_eq!(write(&mut state, &chunk), written, "base64 write {length}");
            assert_eq!(end(&mut state), flushed, "base64 flush {length}");
        }
    }

    #[test]
    fn base64_across_three_writes_matches_node() {
        let mut state = State::new(Encoding::Base64);
        assert_eq!(write(&mut state, b"A"), "");
        assert_eq!(write(&mut state, b"BC"), "QUJD");
        assert_eq!(write(&mut state, b"DEFG"), "REVG");
        assert_eq!(end(&mut state), "Rw==");
    }

    #[test]
    fn base64url_omits_padding() {
        let mut state = State::new(Encoding::Base64Url);
        assert_eq!(write(&mut state, b"A"), "");
        assert_eq!(end(&mut state), "QQ");
    }

    #[test]
    fn hex_and_latin1_and_ascii_never_retain() {
        for encoding in [Encoding::Hex, Encoding::Latin1, Encoding::Ascii] {
            let mut state = State::new(encoding);
            write(&mut state, &[0x01]);
            assert_eq!(state.buffered_bytes(), 0, "{encoding:?} retains nothing");
            assert_eq!(state.missing_bytes(), 0, "{encoding:?} retains nothing");
        }
    }

    #[test]
    fn ascii_masks_the_high_bit_and_latin1_does_not() {
        let mut ascii = State::new(Encoding::Ascii);
        assert_eq!(write(&mut ascii, &[0x41, 0xFF, 0x42]), "A\u{7f}B");
        let mut latin1 = State::new(Encoding::Latin1);
        assert_eq!(write(&mut latin1, &[0x41, 0xFF, 0x42]), "A\u{ff}B");
    }

    #[test]
    fn an_empty_chunk_emits_nothing_and_keeps_the_pending_bytes() {
        let mut state = State::new(Encoding::Utf8);
        write(&mut state, &[0x61, 0xF0]);
        assert_eq!(write(&mut state, b""), "");
        assert_eq!(state.buffered_bytes(), 1);
        assert_eq!(end(&mut state), "\u{FFFD}");
    }

    #[test]
    fn an_unknown_encoding_is_rejected_instead_of_panicking() {
        let mut state = State::new(Encoding::Utf8);
        state.encoding = 42;
        assert!(state.decode(b"x").is_none());
        assert!(state.flush().is_none());
    }

    #[test]
    fn buffer_encoding_is_rejected() {
        // Reachable only by writing `kEncodingField` by hand; Node `CHECK`-fails
        // here, and a `TypeError` is the portable equivalent.
        let mut state = State::new(Encoding::Buffer);
        assert!(state.decode(b"x").is_none());
    }

    #[test]
    fn corrupt_counters_are_rejected_rather_than_overrunning() {
        let mut state = State::new(Encoding::Utf8);
        state.missing = 4;
        state.buffered = 3;
        assert!(state.decode(&[0x80; 4]).is_none());
    }
}
