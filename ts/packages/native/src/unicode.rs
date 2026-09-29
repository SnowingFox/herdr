use napi_derive::napi;

/// Terminal cell width of one codepoint as ghostty computes it (0, 1 or 2).
#[napi]
pub fn unicode_codepoint_width(codepoint: u32) -> u32 {
    u32::from(ghostty_vt::unicode_codepoint_width(codepoint))
}

#[napi(object)]
pub struct GraphemeWidth {
    /// Codepoints consumed as one grapheme cluster.
    pub consumed: u32,
    pub width: u32,
}

/// Width of the first grapheme cluster in `codepoints`.
#[napi]
pub fn unicode_grapheme_width(codepoints: Vec<u32>) -> GraphemeWidth {
    let (consumed, width) = ghostty_vt::unicode_grapheme_width(&codepoints);
    GraphemeWidth {
        consumed: consumed as u32,
        width: u32::from(width),
    }
}
