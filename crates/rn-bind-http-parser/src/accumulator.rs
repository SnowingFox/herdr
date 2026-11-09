//! The header and body accumulation `src/node_http_parser.cc` keeps between
//! callbacks.
//!
//! None of this touches V8, which is the point: the interesting part of the
//! parser is what it does when a header name arrives in three pieces, and that
//! can be tested without an isolate.
//!
//! # Why spans have to be copied
//!
//! llhttp hands `on_header_field(at, length)` a pointer into the caller's
//! buffer. That buffer is a JavaScript `Buffer` whose contents the JS may
//! rewrite as soon as `execute` returns, and llhttp's own `Save()` exists for
//! the same reason (see Node's `StringPtr::Save`). So a span that is still
//! interesting when `execute` returns — the URL, the status message, and any
//! header not yet handed to JavaScript — is copied out here.
//!
//! # The 32-field flush
//!
//! `kMaxHeaderFieldsCount` is 32. Node counts a field *before* checking, so the
//! 32nd header name is the one that triggers the flush, and the pairs handed to
//! `kOnHeaders` at that moment are the 31 that already have both halves. The
//! 32nd name then becomes the first of the next batch:
//!
//! ```text
//! header count    kOnHeaders calls       kOnHeadersComplete sees
//! 31               -                     all 31 pairs
//! 32               [31, 1]               undefined (have_flushed)
//! 33               [31, 2]               undefined
//! 63               [31, 31, 1]           undefined
//! ```
//!
//! The last row is why the batching restarts rather than growing: each batch
//! is bounded, so a hostile client cannot make the parser allocate a header
//! array proportional to its own input.

/// `kMaxHeaderFieldsCount` from `src/node_http_parser.cc`.
pub const MAX_HEADER_FIELDS: usize = 32;

/// A header name or value, possibly assembled from several llhttp spans.
///
/// The common case is one span. A span that continues a previous one appends,
/// which is what makes a header split across TCP packets come out whole.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Span {
    bytes: Vec<u8>,
}

impl Span {
    pub fn push(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    pub fn clear(&mut self) {
        self.bytes.clear();
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The bytes with trailing spaces and tabs removed.
    ///
    /// Only the end: llhttp's grammar already consumes leading whitespace, so
    /// trailing whitespace is the only kind that can survive. Node does this in
    /// `StringPtr::ToTrimmedString`, and only for values.
    pub fn trimmed(&self) -> &[u8] {
        let mut end = self.bytes.len();
        while end > 0 && matches!(self.bytes[end - 1], b' ' | b'\t') {
            end -= 1;
        }
        &self.bytes[..end]
    }
}

/// What an llhttp callback wants done next.
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    Continue,
    /// The batch is full: hand [`Accumulator::flush_batch`] to `kOnHeaders`
    /// before continuing.
    Flush,
}

/// The header pairs accumulated for the current message, plus the URL and
/// status message, which are not header pairs.
#[derive(Debug, Default)]
pub struct Accumulator {
    fields: Vec<Span>,
    values: Vec<Span>,
    url: Span,
    status_message: Span,
    /// Node's `have_flushed_`: set once `kOnHeaders` has run for this message,
    /// after which `on_headers_complete` leaves the headers to that callback
    /// instead of passing them itself.
    flushed: bool,
    /// The header name that triggered a flush. It is held here because the
    /// flush emits the pairs that were complete *before* it, and this name is
    /// the first of the next batch.
    pending_field: Option<Vec<u8>>,
}

impl Accumulator {
    pub fn reset_for_message(&mut self) {
        self.fields.clear();
        self.values.clear();
        self.url.clear();
        self.status_message.clear();
        self.flushed = false;
        self.pending_field = None;
    }

    pub fn url_mut(&mut self) -> &mut Span {
        &mut self.url
    }

    pub fn status_message_mut(&mut self) -> &mut Span {
        &mut self.status_message
    }

    pub fn url(&self) -> &Span {
        &self.url
    }

    pub fn status_message(&self) -> &Span {
        &self.status_message
    }

    pub fn flushed(&self) -> bool {
        self.flushed
    }

    pub fn field_count(&self) -> usize {
        self.fields.len()
    }

    pub fn value_count(&self) -> usize {
        self.values.len()
    }

    /// Whether anything is accumulated that `on_headers_complete` should pass.
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty() && self.values.is_empty()
    }

    /// `on_header_field`: extends the current name or starts the next pair.
    ///
    /// Returns [`Action::Flush`] when this name starts the batch after the one
    /// that just filled up; the caller delivers [`Self::flush_batch`] and then
    /// continues, because the name is already held here.
    pub fn push_field(&mut self, bytes: &[u8]) -> Action {
        if self.fields.len() == self.values.len() {
            self.fields.push(Span::default());
            if self.fields.len() == MAX_HEADER_FIELDS {
                // Node increments the count, sees 32, and flushes. The pair
                // count handed over is the 31 that have values; this 32nd,
                // still-empty name is kept for the next batch.
                self.fields.pop();
                self.pending_field = Some(bytes.to_vec());
                return Action::Flush;
            }
        }
        if let Some(span) = self.fields.last_mut() {
            span.push(bytes);
        }
        Action::Continue
    }

    /// `on_header_value`: extends the current value or starts the next one.
    pub fn push_value(&mut self, bytes: &[u8]) {
        if self.values.len() != self.fields.len() {
            self.values.push(Span::default());
        }
        if let Some(span) = self.values.last_mut() {
            span.push(bytes);
        }
    }

    /// Takes the completed pairs for a `kOnHeaders` call and starts the next
    /// batch with the name that triggered the flush.
    ///
    /// Also clears the URL, because `Flush()` in `src/node_http_parser.cc` ends
    /// with `url_.Reset()`. The first `kOnHeaders` carries the URL and every
    /// later one for the same message gets an empty string, which is what
    /// `parserOnHeaders` relies on when it appends: `this._url += url`.
    ///
    /// The batch is cleared even if the caller never delivers it, so a failing
    /// JavaScript callback cannot leave stale headers behind.
    pub fn flush_batch(&mut self) -> Vec<(Vec<u8>, Vec<u8>)> {
        let pairs = self.pairs_owned();
        self.fields.clear();
        self.values.clear();
        self.url.clear();
        if let Some(name) = self.pending_field.take() {
            let mut field = Span::default();
            field.push(&name);
            self.fields.push(field);
        }
        pairs
    }

    /// The `[name, value, ...]` body for `kOnHeadersComplete`, with values
    /// trimmed.
    ///
    /// Zips, so a name without a value is not reported — which is exactly
    /// Node's `CreateHeaders`, whose loop runs over `num_values_`.
    pub fn pairs(&self) -> Vec<(&[u8], &[u8])> {
        self.fields
            .iter()
            .zip(self.values.iter())
            .map(|(name, value)| (name.bytes(), value.trimmed()))
            .collect()
    }

    fn pairs_owned(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.pairs()
            .into_iter()
            .map(|(name, value)| (name.to_vec(), value.to_vec()))
            .collect()
    }

    /// Drops the pairs, keeping the URL. Used when headers are handed over.
    pub fn clear_pairs(&mut self) {
        self.fields.clear();
        self.values.clear();
    }

    /// Marks that `kOnHeaders` has run for this message.
    pub fn mark_flushed(&mut self) {
        self.flushed = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Alternates names and values, which is what llhttp produces.
    fn feed(accumulator: &mut Accumulator, spans: &[&[u8]]) {
        for (index, span) in spans.iter().enumerate() {
            if index % 2 == 0 {
                accumulator.push_field(span);
            } else {
                accumulator.push_value(span);
            }
        }
    }

    fn names(accumulator: &Accumulator) -> Vec<String> {
        accumulator
            .pairs()
            .iter()
            .map(|(name, value)| {
                format!(
                    "{}={}",
                    String::from_utf8_lossy(name),
                    String::from_utf8_lossy(value)
                )
            })
            .collect()
    }

    #[test]
    fn a_header_split_across_spans_is_one_pair() {
        let mut accumulator = Accumulator::default();
        accumulator.push_field(b"Content-");
        accumulator.push_field(b"Length");
        accumulator.push_value(b"4");
        assert_eq!(names(&accumulator), vec!["Content-Length=4"]);
    }

    #[test]
    fn a_value_split_across_spans_is_joined() {
        let mut accumulator = Accumulator::default();
        accumulator.push_field(b"A");
        accumulator.push_value(b"1");
        accumulator.push_value(b"2");
        assert_eq!(names(&accumulator), vec!["A=12"]);
    }

    #[test]
    fn two_pairs_stay_separate() {
        let mut accumulator = Accumulator::default();
        feed(&mut accumulator, &[b"A", b"1", b"B", b"2"]);
        assert_eq!(names(&accumulator), vec!["A=1", "B=2"]);
    }

    #[test]
    fn trailing_whitespace_is_trimmed_from_values_only() {
        let mut accumulator = Accumulator::default();
        accumulator.push_field(b"A ");
        accumulator.push_value(b"value  \t");
        let (name, value) = accumulator.pairs()[0];
        assert_eq!(name, b"A ", "a field name keeps its trailing space");
        assert_eq!(value, b"value");
    }

    #[test]
    fn an_empty_value_is_an_empty_pair_not_a_missing_one() {
        let mut accumulator = Accumulator::default();
        accumulator.push_field(b"C");
        accumulator.push_value(b"");
        assert_eq!(names(&accumulator), vec!["C="]);
    }

    /// The counts Node produces, verified against a real `node` binary:
    /// 31 headers arrive in one `kOnHeadersComplete`, 32 split into
    /// `kOnHeaders` calls of 31 then 1.
    #[test]
    fn the_thirty_second_field_flushes_31_pairs_and_keeps_the_name() {
        let mut accumulator = Accumulator::default();
        for index in 0..31u32 {
            assert_eq!(
                accumulator.push_field(format!("H{index}").as_bytes()),
                Action::Continue
            );
            accumulator.push_value(b"v");
        }
        assert_eq!(accumulator.field_count(), 31);

        let action = accumulator.push_field(b"H31");
        assert_eq!(action, Action::Flush);
        let flushed = accumulator.flush_batch();
        assert_eq!(flushed.len(), 31, "the 31 complete pairs are handed over");
        assert_eq!(flushed[0].0, b"H0");
        assert_eq!(flushed[30].0, b"H30");

        assert_eq!(
            accumulator.field_count(),
            1,
            "the new name starts the batch"
        );
        accumulator.push_value(b"v");
        assert_eq!(names(&accumulator), vec!["H31=v"]);
    }

    #[test]
    fn a_third_flush_carries_only_what_arrived_since_the_last() {
        let mut accumulator = Accumulator::default();
        let mut batches: Vec<usize> = Vec::new();
        for index in 0..64u32 {
            if accumulator.push_field(format!("H{index}").as_bytes()) == Action::Flush {
                batches.push(accumulator.flush_batch().len());
            }
            accumulator.push_value(b"v");
        }
        // Node reports [31, 31, 2] for 64 headers: two full batches of 31, then
        // the 2 left over when the message completes.
        assert_eq!(batches, vec![31, 31]);
        assert_eq!(accumulator.pairs().len(), 2);
    }

    #[test]
    fn flush_batch_clears_even_when_nothing_was_pending() {
        let mut accumulator = Accumulator::default();
        feed(&mut accumulator, &[b"A", b"1"]);
        assert_eq!(accumulator.flush_batch().len(), 1);
        assert_eq!(accumulator.field_count(), 0);
        assert_eq!(accumulator.value_count(), 0);
    }

    #[test]
    fn a_flush_consumes_the_url() {
        let mut accumulator = Accumulator::default();
        accumulator.url_mut().push(b"/path");
        feed(&mut accumulator, &[b"A", b"1"]);
        accumulator.flush_batch();
        assert_eq!(
            accumulator.url().bytes(),
            b"",
            "Flush() ends with url_.Reset(), so only the first kOnHeaders sees it"
        );
    }

    #[test]
    fn the_url_is_still_there_before_any_flush() {
        let mut accumulator = Accumulator::default();
        accumulator.url_mut().push(b"/path");
        assert_eq!(accumulator.url().bytes(), b"/path");
    }
}
