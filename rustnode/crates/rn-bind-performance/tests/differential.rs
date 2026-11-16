//! Differential test: `perf_hooks` histograms against the pinned Node oracle.
//!
//! The recorded divergence this file guards is that `createHistogram()` threw
//! `_Histogram is not a constructor`: both classes were in the bindings
//! contract's `MEMBERS` and installed as `undefined`. A test that only asserted
//! "it built" would have passed as soon as the constructor existed, whatever the
//! accessors returned, so every assertion here compares *values* produced by the
//! same script on both runtimes.
//!
//! # Why the same script runs twice
//!
//! The histogram is bucket arithmetic whose edges are not obvious: `max` is the
//! upper edge of the bucket the largest sample landed in, `mean` is computed over
//! bucket medians, and `percentiles` reports bucket *lower* edges where
//! `percentile(p)` reports upper ones. Re-deriving those expectations by hand
//! would pin whatever the implementation happens to do. Running one script under
//! both runtimes and comparing the text makes the oracle the authority.
//!
//! # What is NOT compared
//!
//! `recordDelta` and the ELD sampling intervals measure wall-clock time, so their
//! values differ between two runs of the same binary. Those cases assert the
//! *shape* — that something was recorded and the value is positive — on both
//! sides, and are marked below.

use std::path::PathBuf;
use std::process::Command;

fn rustnode() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("target");
    path.push(if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    });
    path.push("rustnode");
    path
}

/// Runs `script` under `binary` with `-e`, returning trimmed stdout.
fn eval(binary: &std::path::Path, script: &str) -> String {
    let output = Command::new(binary)
        .arg("-e")
        .arg(script)
        .output()
        .unwrap_or_else(|error| panic!("cannot run {}: {error}", binary.display()));
    assert!(
        output.status.success(),
        "{} failed on the histogram probe:\n{}\n--- stderr ---\n{}",
        binary.display(),
        script,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

/// Runs `script` under both runtimes and asserts the output is identical.
///
/// Returns the output so a caller can additionally assert a property of it, which
/// is what keeps this from being a comparison that passes when both sides fail
/// identically.
fn same_as_oracle(oracle: &rn_node_oracle::Oracle, script: &str) -> String {
    let expected = eval(&oracle.path, script);
    let actual = eval(&rustnode(), script);
    assert_eq!(
        actual,
        expected,
        "histogram output differs from {}. Script:\n{script}",
        oracle.describe()
    );
    actual
}

/// The shared prologue: one helper that renders a value the way both runtimes
/// agree on, plus the sample set most cases use.
const PROLOGUE: &str = r#"
const { createHistogram, createSlidingWindowHistogram } = require('perf_hooks');
function render(value) {
  if (typeof value === 'bigint') return `${value}n`;
  if (value instanceof Map) {
    return JSON.stringify([...value.entries()].map(([k, v]) =>
      [k, typeof v === 'bigint' ? `${v}n` : v]));
  }
  return String(value);
}
const samples = [1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 377, 610, 987];
"#;

#[test]
fn every_scalar_accessor_matches_the_oracle() {
    let Some(oracle) = rn_node_oracle::require_oracle("the perf_hooks histogram accessors") else {
        return;
    };
    let output = same_as_oracle(
        &oracle,
        &format!(
            "{PROLOGUE}
            const h = createHistogram({{ lowest: 1, highest: 1000, figures: 3 }});
            for (const value of samples) h.record(value);
            for (const name of ['count', 'countBigInt', 'min', 'minBigInt', 'max',
                                'maxBigInt', 'mean', 'stddev', 'exceeds', 'exceedsBigInt',
                                'skewness', 'kurtosis', 'ewmaMean', 'ewmaStddev',
                                'ewmaErrorRate', 'resetCount']) {{
              console.log(`${{name}}=${{render(h[name])}}`);
            }}
            for (const percentile of [1, 10, 50, 90, 99, 99.9, 100]) {{
              console.log(`p${{percentile}}=${{h.percentile(percentile)}}`);
              console.log(`pb${{percentile}}=${{render(h.percentileBigInt(percentile))}}`);
            }}"
        ),
    );
    // Spot checks so a both-sides-empty comparison cannot pass.
    assert!(output.contains("count=15"), "{output}");
    assert!(output.contains("min=1"), "{output}");
    assert!(output.contains("p50=34"), "{output}");
}

#[test]
fn the_percentile_tables_match_the_oracle() {
    // Two iterators, two different values for the same bucket: `percentiles`
    // reports the lowest equivalent value and `percentile()` the highest. The
    // tables are where that shows up, so they are compared separately.
    let Some(oracle) = rn_node_oracle::require_oracle("the perf_hooks percentile tables") else {
        return;
    };
    let output = same_as_oracle(
        &oracle,
        &format!(
            "{PROLOGUE}
            for (const figures of [1, 2, 3]) {{
              const h = createHistogram({{ lowest: 1, highest: 1000, figures }});
              for (const value of [100, 200, 300, 400]) h.record(value);
              console.log(`f${{figures}} percentiles=${{render(h.percentiles)}}`);
              console.log(`f${{figures}} bigint=${{render(h.percentilesBigInt)}}`);
              console.log(`f${{figures}} at=${{render(h.percentilesAt([1, 25, 50, 75, 99, 100]))}}`);
              console.log(`f${{figures}} p100=${{h.percentile(100)}}`);
            }}"
        ),
    );
    // At one significant figure the buckets are coarse enough that the two
    // tables must disagree; that is the property the port has to preserve.
    assert!(
        output.contains("f1 percentiles=[[0,100],[50,200],[75,288],[87.5,400],[100,400]]"),
        "{output}"
    );
    assert!(output.contains("f1 p100=415"), "{output}");
}

#[test]
fn the_bucket_aggregations_match_the_oracle() {
    let Some(oracle) = rn_node_oracle::require_oracle("the perf_hooks bucket aggregations") else {
        return;
    };
    let output = same_as_oracle(
        &oracle,
        &format!(
            "{PROLOGUE}
            const h = createHistogram({{ lowest: 1, highest: 1000, figures: 2 }});
            for (const value of samples) h.record(value);
            console.log(`linear=${{render(h.linearBuckets(100))}}`);
            console.log(`log2=${{render(h.logBuckets(10, 2))}}`);
            console.log(`log15=${{render(h.logBuckets(10, 1.5))}}`);
            for (const value of [0, 1, 8, 9, 100, 10000]) {{
              console.log(`countAt(${{value}})=${{h.countAt(value)}}`);
              console.log(`cdf(${{value}})=${{h.cdf(value)}}`);
            }}
            const empty = createHistogram({{ lowest: 1, highest: 1000, figures: 2 }});
            console.log(`emptyLinear=${{render(empty.linearBuckets(100))}}`);
            console.log(`emptyLog=${{render(empty.logBuckets(10, 2))}}`);
            console.log(`emptyAt=${{render(empty.percentilesAt([25, 50]))}}`);"
        ),
    );
    // An empty histogram yields no bucket rows at all, which is the termination
    // rule a naive "emit every step up to the maximum" implementation gets wrong.
    assert!(output.contains("emptyLinear=[]"), "{output}");
    assert!(output.contains("emptyLog=[]"), "{output}");
}

#[test]
fn the_defaults_match_the_oracle() {
    // No options at all: the layout covers the whole int64 range, so `maxBigInt`
    // is where the top bucket's saturation shows up.
    let Some(oracle) = rn_node_oracle::require_oracle("the perf_hooks histogram defaults") else {
        return;
    };
    let output = same_as_oracle(
        &oracle,
        &format!(
            "{PROLOGUE}
            const h = createHistogram();
            for (const value of samples) h.record(value);
            console.log(`count=${{h.count}} min=${{h.min}} max=${{h.max}}`);
            console.log(`maxBigInt=${{render(h.maxBigInt)}}`);
            console.log(`minBigInt=${{render(h.minBigInt)}}`);
            console.log(`p50=${{h.percentile(50)}}`);"
        ),
    );
    assert!(output.contains("count=15"), "{output}");
}

#[test]
fn recording_zero_and_bigint_samples_matches_the_oracle() {
    let Some(oracle) = rn_node_oracle::require_oracle("the perf_hooks zero and bigint paths")
    else {
        return;
    };
    let output = same_as_oracle(
        &oracle,
        &format!(
            "{PROLOGUE}
            const zero = createHistogram({{ lowest: 1, highest: 1000, figures: 3 }});
            zero.record(0);
            zero.record(10);
            console.log(`zero min=${{zero.min}} count=${{zero.count}}`);

            const big = createHistogram({{ lowest: 1n, highest: 1000n, figures: 3 }});
            big.record(10n);
            big.record(20);
            console.log(`big count=${{big.count}} min=${{render(big.minBigInt)}}`);"
        ),
    );
    // A recorded zero does not move `min_value`, but `hdr_min` reports 0 because
    // bucket 0 holds a count. A port that only read the stored minimum would say
    // 10 here.
    assert!(output.contains("zero min=0"), "{output}");
}

#[test]
fn the_ewma_counters_match_the_oracle() {
    // The EWMA is opt-in through `halfLife`, and `threshold` arms the SLO error
    // rate. Both are pure arithmetic over the recorded values, so they compare
    // exactly.
    let Some(oracle) = rn_node_oracle::require_oracle("the perf_hooks EWMA counters") else {
        return;
    };
    let output = same_as_oracle(
        &oracle,
        &format!(
            "{PROLOGUE}
            const h = createHistogram({{
              lowest: 1, highest: 1000, figures: 3, halfLife: 4, threshold: 100,
            }});
            for (const value of [10, 200, 20, 300, 30]) h.record(value);
            console.log(`mean=${{h.ewmaMean}} stddev=${{h.ewmaStddev}} rate=${{h.ewmaErrorRate}}`);
            console.log(`burn=${{h.burnRate(0.999)}}`);"
        ),
    );
    // The oracle's exact EWMA values, so a both-sides-unchanged comparison cannot
    // pass by agreeing on a zero.
    assert!(output.contains("mean=71.08077373651453"), "{output}");
    assert!(output.contains("rate=0.22839319156852758"), "{output}");
}

#[test]
fn the_arithmetic_operations_match_the_oracle() {
    let Some(oracle) = rn_node_oracle::require_oracle("the perf_hooks histogram arithmetic") else {
        return;
    };
    let output = same_as_oracle(
        &oracle,
        &format!(
            "{PROLOGUE}
            const left = createHistogram({{ lowest: 1, highest: 1000, figures: 3 }});
            const right = createHistogram({{ lowest: 1, highest: 1000, figures: 3 }});
            for (const value of [10, 20, 30]) left.record(value);
            for (const value of [40, 50]) right.record(value);
            left.add(right);
            console.log(`added count=${{left.count}} min=${{left.min}} max=${{left.max}}`);

            const self = createHistogram({{ lowest: 1, highest: 1000, figures: 3 }});
            self.record(10);
            self.record(20);
            self.add(self);
            console.log(`self count=${{self.count}}`);

            const base = createHistogram({{ lowest: 1, highest: 1000, figures: 3 }});
            base.record(10);
            base.record(20);
            const snapshot = base.snapshot();
            base.record(30);
            base.record(40);
            console.log(`snapshot count=${{snapshot.count}} base count=${{base.count}}`);
            const difference = base.diff(snapshot);
            console.log(`diff count=${{difference.count}} min=${{difference.min}}`);

            const dropped = createHistogram({{ lowest: 1, highest: 1000, figures: 3 }});
            dropped.record(10);
            dropped.subtract(right);
            console.log(`subtract count=${{dropped.count}} reset=${{dropped.resetCount}}`);
            try {{
              dropped.diff(snapshot);
              console.log('diffAfterSubtract=no-throw');
            }} catch (error) {{
              console.log(`diffAfterSubtract=${{error.code}}`);
            }}"
        ),
    );
    assert!(output.contains("added count=5"), "{output}");
    assert!(output.contains("self count=4"), "{output}");
    assert!(
        output.contains("diffAfterSubtract=ERR_INVALID_STATE"),
        "{output}"
    );
}

#[test]
fn the_argument_errors_match_the_oracle() {
    // A caller branches on `error.code`, so the codes have to agree and not only
    // the fact that something was thrown.
    let Some(oracle) = rn_node_oracle::require_oracle("the perf_hooks histogram errors") else {
        return;
    };
    let output = same_as_oracle(
        &oracle,
        r#"
        const { createHistogram, createSlidingWindowHistogram, importHistogram } =
          require('perf_hooks');
        const attempt = (label, body) => {
          try { body(); console.log(`${label}=no-throw`); }
          catch (error) { console.log(`${label}=${error.code || error.name}`); }
        };
        attempt('percentile0', () => createHistogram().percentile(0));
        attempt('percentile101', () => createHistogram().percentile(101));
        attempt('highestTooSmall', () => createHistogram({ lowest: 100, highest: 100 }));
        attempt('figures0', () => createHistogram({ figures: 0 }));
        attempt('figures6', () => createHistogram({ figures: 6 }));
        attempt('recordNegative', () => createHistogram().record(-1));
        attempt('recordFloat', () => createHistogram().record(1.5));
        attempt('slidingBoth', () =>
          createSlidingWindowHistogram({ chunks: 2, chunkDuration: 10, recordsPerChunk: 5 }));
        attempt('slidingNeither', () => createSlidingWindowHistogram({ chunks: 2 }));
        attempt('slidingChunks0', () =>
          createSlidingWindowHistogram({ chunks: 0, recordsPerChunk: 1 }));
        attempt('importNotBytes', () => importHistogram('nope'));"#,
    );
    assert!(output.contains("percentile0=ERR_OUT_OF_RANGE"), "{output}");
    assert!(
        output.contains("recordNegative=ERR_OUT_OF_RANGE"),
        "{output}"
    );
    assert!(
        output.contains("slidingBoth=ERR_INVALID_ARG_VALUE"),
        "{output}"
    );
    assert!(
        output.contains("importNotBytes=ERR_INVALID_ARG_TYPE"),
        "{output}"
    );
}

#[test]
fn the_sliding_window_matches_the_oracle() {
    let Some(oracle) = rn_node_oracle::require_oracle("the sliding window histogram") else {
        return;
    };
    let output = same_as_oracle(
        &oracle,
        &format!(
            "{PROLOGUE}
            const byRecords = createSlidingWindowHistogram({{
              chunks: 2, recordsPerChunk: 2, lowest: 1, highest: 1000, figures: 2,
            }});
            for (const value of [10, 20, 30, 40]) byRecords.record(value);
            const window = byRecords.snapshot();
            console.log(`window count=${{window.count}} min=${{window.min}} max=${{window.max}}`);
            console.log(`window p50=${{window.percentile(50)}}`);

            const widened = createSlidingWindowHistogram({{
              chunks: 3, recordsPerChunk: 2, lowest: 1, highest: 1000, figures: 2,
            }});
            for (const value of [10, 20, 30, 40]) widened.record(value);
            const wide = widened.snapshot();
            console.log(`wide count=${{wide.count}} min=${{wide.min}}`);

            widened.reset();
            const afterReset = widened.snapshot();
            console.log(`afterReset count=${{afterReset.count}}`);"
        ),
    );
    // Two chunks of two records hold four records exactly, so all four survive;
    // three chunks hold six of the four recorded. A ring that dropped nothing
    // would report the same here, which is why the differential equality above
    // is the assertion and these only stop a both-empty comparison.
    assert!(output.contains("window count=4"), "{output}");
    assert!(output.contains("wide count=4"), "{output}");
    assert!(output.contains("afterReset count=0"), "{output}");
}

#[test]
fn an_eld_histogram_records_positive_delays() {
    // The values are wall-clock measurements, so the two runtimes cannot produce
    // the same numbers and this compares each side against the same *properties*
    // instead: at least one interval recorded, and every statistic consistent with
    // a non-empty histogram of positive nanosecond delays.
    //
    // `monitorEventLoopDelay()` is the case that used to throw, because it builds
    // an ELD handle through the same subsystem `createHistogram` needed.
    let Some(oracle) = rn_node_oracle::require_oracle("the perf_hooks event loop delay") else {
        return;
    };
    // The loop has to run for the interval timer to fire: a busy wait blocks the
    // loop and records nothing in either runtime. The measurement therefore
    // happens from a `setTimeout`, which is also what makes the enable/disable
    // return values observable in the right order.
    let script = r#"
        const { monitorEventLoopDelay } = require('perf_hooks');
        const results = [];
        let pending = 2;
        for (const samplePerIteration of [false, true]) {
          const histogram = monitorEventLoopDelay({ resolution: 1, samplePerIteration });
          const before = histogram.count;
          histogram.enable();
          const enableAgain = histogram.enable();
          setTimeout(() => {
            const disable = histogram.disable();
            const disableAgain = histogram.disable();
            results.push([
              before, enableAgain, disable, disableAgain,
              histogram.count > 0, histogram.min > 0,
              Number.isFinite(histogram.mean), histogram.max >= histogram.min,
            ].join(' '));
            pending -= 1;
            if (pending === 0) console.log(results.join('\n'));
          }, 25);
        }"#;
    let expected = eval(&oracle.path, script);
    let actual = eval(&rustnode(), script);
    assert_eq!(
        actual,
        expected,
        "the event-loop-delay histogram differs from {}",
        oracle.describe()
    );
    // Both modes recorded something positive and the enable/disable trio is
    // `false`/`true`/`false`; a both-empty comparison would otherwise satisfy the
    // equality above.
    assert_eq!(
        actual,
        "0 false true false true true true true\n0 false true false true true true true"
    );
}

#[test]
fn the_exported_payload_matches_the_oracle_byte_for_byte() {
    // `export()` is a wire format: an exported histogram outlives the process
    // that wrote it, so a peer decodes it with Node's importer. A payload that
    // merely round-trips through this implementation's own decoder would pass a
    // looser test and still be unreadable by Node, which is why the comparison
    // is on the bytes.
    let Some(oracle) = rn_node_oracle::require_oracle("the histogram export format") else {
        return;
    };
    let script = r#"
        const { createHistogram } = require('perf_hooks');
        const cases = [
          { lowest: 1, highest: 1000, figures: 3 },
          { lowest: 1, highest: 100, figures: 1 },
          { lowest: 1, highest: 1000000, figures: 5 },
          { lowest: 1, highest: 1000, figures: 3, halfLife: 4, threshold: 100 },
        ];
        for (const options of cases) {
          const h = createHistogram(options);
          for (const value of [1, 10, 100, 1000, 200, 20]) {
            try { h.record(value); } catch {}
          }
          console.log(Buffer.from(h.export()).toString('hex'));
        }"#;
    let expected = eval(&oracle.path, script);
    let actual = eval(&rustnode(), script);
    assert_eq!(
        actual,
        expected,
        "the export payload differs from {}",
        oracle.describe()
    );
    // Four non-empty payloads, all starting with an 11- or 12-entry CBOR map.
    assert_eq!(actual.lines().count(), 4, "{actual}");
    assert!(
        actual
            .lines()
            .all(|line| line.starts_with("ab") || line.starts_with("ac")),
        "{actual}"
    );
}

#[test]
fn an_imported_payload_matches_the_oracle() {
    // The decoder has to accept exactly what the encoder produces and reject
    // what Node rejects. The bytes are supplied as hex so both runtimes import
    // the *same* payload rather than each other's.
    let Some(oracle) = rn_node_oracle::require_oracle("the histogram import path") else {
        return;
    };
    let script = r#"
        const { createHistogram, importHistogram } = require('perf_hooks');
        const original = createHistogram({ lowest: 1, highest: 1000, figures: 3 });
        for (const value of [10, 20, 30, 40, 50]) original.record(value);
        const payload = Buffer.from(original.export());
        const back = importHistogram(payload);
        console.log(back.count, back.min, back.max, back.mean, back.percentile(50));
        // A record after import continues the same histogram.
        back.record(60);
        console.log(back.count, back.max);
        // Truncation, a non-Uint8Array, and a byte-flipped payload are all
        // rejections rather than silent repairs.
        for (const bad of [
          payload.subarray(0, payload.length - 3),
          'not bytes',
          (() => { const copy = Buffer.from(payload); copy[copy.length - 1] ^= 0xff; return copy; })(),
        ]) {
          try { importHistogram(bad); console.log('accepted'); }
          catch (error) { console.log(`${error.code || error.name}`); }
        }"#;
    let expected = eval(&oracle.path, script);
    let actual = eval(&rustnode(), script);
    assert_eq!(
        actual,
        expected,
        "the import path differs from {}",
        oracle.describe()
    );
    assert!(actual.starts_with("5 10 50 30 30"), "{actual}");
}
