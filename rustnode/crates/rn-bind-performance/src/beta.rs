//! The regularized incomplete beta function in both shapes Node uses.
//!
//! `src/histogram.cc` has one core routine and two ways to reach it:
//!
//! * `RegularizedIncompleteBeta(a, b, x)` builds a [`BetaParameters`] with
//!   `approximate_large_shapes = false` and returns the CDF alone. That is the
//!   path `StudentTCdf` and `BinomialCdf` take, so it backs `meanCI`,
//!   `percentileCI`, `welchTest` and `mannWhitneyTest`.
//! * `RegularizedIncompleteBeta(params, x, front_out)` takes the parameters
//!   built with `approximate_large_shapes = true` and can also report the
//!   "front" term. That is the path `qrde` takes, where the front is the density
//!   factor the quantile integral needs and where a large-shape Edgeworth
//!   expansion replaces the continued fraction.
//!
//! Both live here, sharing one [`beta_continued_fraction`], because the two
//! differ only in how the parameters are prepared and in whether a front is
//! wanted. Keeping them apart would be a second copy of the same series with its
//! own convergence behaviour.
//!
//! # Why `lgamma` and `erfc` come from libc
//!
//! Node calls `std::lgamma` and `std::erfc`, which on glibc are the C library's
//! correctly-rounded-ish implementations. A Lanczos approximation written in
//! Rust agrees with glibc to about 1e-15 *relative*, which sounds harmless until
//! it is exponentiated into the front term and then divided by a beta shape: the
//! `qrde` regression tests compare quantiles at 2e-13 absolute against values
//! whose computation involves `lgamma(sum)` with `sum` in the thousands. Calling
//! the same functions Node calls removes that whole axis of disagreement, and it
//! costs two `extern` declarations rather than a dependency.

/// `std::lgamma`, as glibc implements it.
///
/// # Safety
///
/// None: the function is pure and total over the doubles `BetaParameters`
/// produces (positive shape parameters).
fn lgamma(x: f64) -> f64 {
    unsafe { c::lgamma(x) }
}

/// `std::erfc`.
fn erfc(x: f64) -> f64 {
    unsafe { c::erfc(x) }
}

mod c {
    unsafe extern "C" {
        pub fn lgamma(x: f64) -> f64;
        pub fn erfc(x: f64) -> f64;
    }
}

/// `BetaContinuedFraction`: continued fraction for the regularized incomplete
/// beta function using Lentz's modified method.
///
/// Reference: Numerical Recipes in C, 2nd edition, section 6.4 — the comment
/// Node carries, and the reason `EPS` is `3e-12` rather than a tighter value.
fn beta_continued_fraction(a: f64, b: f64, x: f64) -> f64 {
    const FPMIN: f64 = 1e-30;
    const MAXIT: usize = 200;
    const EPS: f64 = 3e-12;

    let qab = a + b;
    let qap = a + 1.0;
    let qam = a - 1.0;
    let mut c = 1.0;
    let mut d = 1.0 - qab * x / qap;
    if d.abs() < FPMIN {
        d = FPMIN;
    }
    d = 1.0 / d;
    let mut h = d;

    for m in 1..=MAXIT {
        let m2 = 2.0 * m as f64;
        let mut aa = m as f64 * (b - m as f64) * x / ((qam + m2) * (a + m2));
        d = 1.0 + aa * d;
        if d.abs() < FPMIN {
            d = FPMIN;
        }
        c = 1.0 + aa / c;
        if c.abs() < FPMIN {
            c = FPMIN;
        }
        d = 1.0 / d;
        h *= d * c;

        aa = -(a + m as f64) * (qab + m as f64) * x / ((a + m2) * (qap + m2));
        d = 1.0 + aa * d;
        if d.abs() < FPMIN {
            d = FPMIN;
        }
        c = 1.0 + aa / c;
        if c.abs() < FPMIN {
            c = FPMIN;
        }
        d = 1.0 / d;
        let delta = d * c;
        h *= delta;
        if (delta - 1.0).abs() <= EPS {
            break;
        }
    }
    h
}

/// `StirlingCorrection`: the `1/(12x) - 1/(360x^3) + ...` tail of Stirling's
/// series, which the asymptotic beta front term needs in place of `lgamma`.
fn stirling_correction(x: f64) -> f64 {
    let inverse = 1.0 / x;
    let inverse_squared = inverse * inverse;
    inverse
        * (1.0 / 12.0
            + inverse_squared
                * (-1.0 / 360.0
                    + inverse_squared
                        * (1.0 / 1260.0
                            + inverse_squared * (-1.0 / 1680.0 + inverse_squared / 1188.0))))
}

/// `BetaParameters`, the precomputed shape facts both the CDF and the front need.
pub(crate) struct BetaParameters {
    a: f64,
    b: f64,
    log_normalization: f64,
    mean: f64,
    standard_deviation: f64,
    skewness: f64,
    excess_kurtosis: f64,
    log_scale: f64,
    symmetry_point: f64,
    use_asymptotic_front: bool,
    use_asymptotic_cdf: bool,
}

impl BetaParameters {
    /// The distribution's mean, `a / (a + b)`. `qrde`'s support search reads it to
    /// pick the integration window.
    pub(crate) fn mean(&self) -> f64 {
        self.mean
    }

    /// The distribution's standard deviation, which sizes the same window.
    pub(crate) fn standard_deviation(&self) -> f64 {
        self.standard_deviation
    }

    /// `(a + 1) / (a + b + 2)`, the point past which `qrde` switches to the
    /// reflected CDF so it never subtracts a small tail weight from one.
    pub(crate) fn symmetry_point(&self) -> f64 {
        self.symmetry_point
    }

    /// Whether the Edgeworth expansion replaces the continued fraction.
    pub(crate) fn uses_asymptotic_cdf(&self) -> bool {
        self.use_asymptotic_cdf
    }
}

/// `MakeBetaParameters`.
///
/// `approximate_large_shapes` is `false` for the scalar entry point, which is
/// what makes `StudentTCdf`'s call exact: at the degrees of freedom a confidence
/// interval uses, `a` and `b` are far below the asymptotic thresholds anyway, so
/// the flag only decides whether the *checks* run.
pub(crate) fn beta_parameters(a: f64, b: f64, approximate_large_shapes: bool) -> BetaParameters {
    let sum = a + b;
    let mean = a / sum;
    let use_asymptotic_front = approximate_large_shapes && a >= 8.0 && b >= 8.0;
    // The continued fraction needs progressively more iterations as both beta
    // shapes grow; at this concentration the Edgeworth error is smaller than the
    // continued-fraction truncation error, which is the trade Node makes.
    let use_asymptotic_cdf = approximate_large_shapes && a * b / sum >= 25_000.0;
    let variance = mean * (1.0 - mean) / (sum + 1.0);
    let skewness = 2.0 * (b - a) * (sum + 1.0).sqrt() / ((sum + 2.0) * (a * b).sqrt());
    let excess_kurtosis = 6.0 * ((a - b) * (a - b) * (sum + 1.0) - a * b * (sum + 2.0))
        / (a * b * (sum + 2.0) * (sum + 3.0));
    BetaParameters {
        a,
        b,
        log_normalization: if use_asymptotic_front {
            0.0
        } else {
            lgamma(sum) - lgamma(a) - lgamma(b)
        },
        mean,
        standard_deviation: variance.sqrt(),
        skewness,
        excess_kurtosis,
        log_scale: if use_asymptotic_front {
            0.5 * (sum * mean * (1.0 - mean) / (2.0 * std::f64::consts::PI)).ln()
                + stirling_correction(sum)
                - stirling_correction(a)
                - stirling_correction(b)
        } else {
            0.0
        },
        symmetry_point: (a + 1.0) / (sum + 2.0),
        use_asymptotic_front,
        use_asymptotic_cdf,
    }
}

/// `ReflectBetaParameters`: the same distribution seen from `1 - x`.
pub(crate) fn reflect_beta_parameters(params: &BetaParameters) -> BetaParameters {
    BetaParameters {
        a: params.b,
        b: params.a,
        log_normalization: params.log_normalization,
        mean: 1.0 - params.mean,
        standard_deviation: params.standard_deviation,
        skewness: -params.skewness,
        excess_kurtosis: params.excess_kurtosis,
        log_scale: params.log_scale,
        symmetry_point: 1.0 - params.symmetry_point,
        use_asymptotic_front: params.use_asymptotic_front,
        use_asymptotic_cdf: params.use_asymptotic_cdf,
    }
}

/// `BetaFront`: `x^a (1-x)^b / B(a, b)`, the density factor both the continued
/// fraction path and `qrde`'s within-bucket moment need.
///
/// The asymptotic form is a log1p expansion around the mean, which keeps the
/// relative error of the exponent small where `x` and `mean` are close; the exact
/// form would subtract two large logarithms there.
pub(crate) fn beta_front(params: &BetaParameters, x: f64) -> f64 {
    if x <= 0.0 || x >= 1.0 {
        return 0.0;
    }
    let log_front = if params.use_asymptotic_front {
        params.a * ((x - params.mean) / params.mean).ln_1p()
            + params.b * ((params.mean - x) / (1.0 - params.mean)).ln_1p()
            + params.log_scale
    } else {
        params.log_normalization + params.a * x.ln() + params.b * (1.0 - x).ln()
    };
    log_front.exp()
}

/// `AsymptoticBetaCdf`: the Edgeworth expansion Node substitutes for the
/// continued fraction once both shapes are large.
fn asymptotic_beta_cdf(params: &BetaParameters, x: f64, front_out: &mut f64) -> f64 {
    let z = (x - params.mean) / params.standard_deviation;
    let normal_cdf = 0.5 * erfc(-z / std::f64::consts::SQRT_2);
    if z.abs() >= 8.0 {
        *front_out = 0.0;
        return normal_cdf;
    }

    let z2 = z * z;
    let z3 = z2 * z;
    let normal_pdf = (-0.5 * z2).exp() / (2.0 * std::f64::consts::PI).sqrt();
    let z4 = z2 * z2;
    let z6 = z3 * z3;
    let density_correction = 1.0
        + params.skewness / 6.0 * (z3 - 3.0 * z)
        + params.excess_kurtosis / 24.0 * (z4 - 6.0 * z2 + 3.0)
        + params.skewness * params.skewness / 72.0 * (z6 - 15.0 * z4 + 45.0 * z2 - 15.0);
    *front_out =
        x * (1.0 - x) * normal_pdf / params.standard_deviation * density_correction.max(0.0);

    let correction = params.skewness / 6.0 * (1.0 - z2)
        - params.excess_kurtosis / 24.0 * (z3 - 3.0 * z)
        - params.skewness * params.skewness / 72.0 * (z3 * z2 - 10.0 * z3 + 15.0 * z);
    clamp(normal_cdf + normal_pdf * correction, 0.0, 1.0)
}

/// `RegularizedIncompleteBeta(params, x, front_out)`: `I_x(a, b)` and, when the
/// caller asks, the front term that came with it.
pub(crate) fn regularized_incomplete_beta_with_front(
    params: &BetaParameters,
    x: f64,
    want_front: bool,
) -> (f64, f64) {
    if x <= 0.0 {
        return (0.0, 0.0);
    }
    if x >= 1.0 {
        return (1.0, 0.0);
    }
    if params.use_asymptotic_cdf {
        let mut front = 0.0;
        let cdf = asymptotic_beta_cdf(params, x, &mut front);
        return (cdf, if want_front { front } else { 0.0 });
    }

    let front = beta_front(params, x);
    // The symmetry relation keeps the continued fraction in the region where it
    // converges fastest.
    let cdf = if x < params.symmetry_point {
        front * beta_continued_fraction(params.a, params.b, x) / params.a
    } else {
        1.0 - front * beta_continued_fraction(params.b, params.a, 1.0 - x) / params.b
    };
    (cdf, if want_front { front } else { 0.0 })
}

/// `RegularizedIncompleteBeta(a, b, x)`: the CDF alone, with exact parameters.
///
/// This is the shape `StudentTCdf` and `BinomialCdf` call, so it is what
/// `meanCI`, `percentileCI`, `welchTest` and `mannWhitneyTest` are built on.
pub(crate) fn regularized_incomplete_beta(a: f64, b: f64, x: f64) -> f64 {
    regularized_incomplete_beta_with_front(&beta_parameters(a, b, false), x, false).0
}

/// `NormalCdf`: `Phi(x) = P(Z <= x)`.
pub(crate) fn normal_cdf(x: f64) -> f64 {
    0.5 * erfc(-x * std::f64::consts::SQRT_2 / 2.0)
}

/// `StudentTCdf`: `P(T <= t)` for `df` degrees of freedom.
///
/// Two branches, both Node's: squaring `t` and comparing it against `df` decides
/// which of the two beta parameters is the small one, and the answer is built from
/// the CDF on that side. Evaluating the formula unconditionally loses precision in
/// the tail, which is where the confidence intervals live.
pub(crate) fn student_t_cdf(t: f64, df: f64) -> f64 {
    let squared = t * t;
    let denominator = df + squared;
    if squared < df {
        let x = squared / denominator;
        let ibeta = regularized_incomplete_beta(0.5, df / 2.0, x);
        if t >= 0.0 {
            0.5 + 0.5 * ibeta
        } else {
            0.5 - 0.5 * ibeta
        }
    } else {
        let x = df / denominator;
        let ibeta = regularized_incomplete_beta(df / 2.0, 0.5, x);
        if t >= 0.0 {
            1.0 - 0.5 * ibeta
        } else {
            0.5 * ibeta
        }
    }
}

/// `StudentTUpperQuantile`: the positive t whose upper-tail probability is `p`.
///
/// A bisection rather than an inverse-series approximation, because that is what
/// Node does: the search starts at `[0, 1]` and doubles the upper bound until the
/// lower tail is below `p`, then halves the interval 100 times. The result is
/// therefore the exactly-representable value the same bisection lands on, which is
/// what a `meanCI` compared to 1e-13 against the oracle needs.
pub(crate) fn student_t_upper_quantile(mut p: f64, df: f64) -> f64 {
    // Node's signature takes the probability and does not clamp it; a `p` of `0`
    // or below makes the `while` below run until the bound overflows, so the clamp
    // is what keeps a `confidence` of exactly `1` from looping forever. The JS
    // layer rejects those values, so this only guards a direct native call.
    if !(p > 0.0) {
        p = f64::MIN_POSITIVE;
    }
    let mut lo = 0.0_f64;
    let mut hi = 1.0_f64;
    while student_t_cdf(-hi, df) > p {
        hi *= 2.0;
        if !hi.is_finite() {
            return f64::INFINITY;
        }
    }

    for _ in 0..100 {
        let mid = (lo + hi) / 2.0;
        if student_t_cdf(-mid, df) > p {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    (lo + hi) / 2.0
}

/// `std::clamp(value, lower, upper)`.
///
/// Deliberately written as the ternary chain rather than `f64::clamp`: the C++
/// version never panics on `lower > upper` and returns `value` unchanged for a
/// NaN, and `qrde` reaches it with bounds derived from a CDF that can be NaN
/// when a beta shape underflows. Panicking there would turn a numeric edge case
/// into an abort, and clamping a NaN to a bound would silently invent a quantile.
pub(crate) fn clamp(value: f64, lower: f64, upper: f64) -> f64 {
    if value < lower {
        lower
    } else if value > upper {
        upper
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The CDF is monotone and lands on both endpoints, which is the one property
    /// every caller depends on.
    #[test]
    fn the_regularized_incomplete_beta_brackets_its_argument() {
        assert_eq!(regularized_incomplete_beta(2.0, 3.0, 0.0), 0.0);
        assert_eq!(regularized_incomplete_beta(2.0, 3.0, 1.0), 1.0);
        let mut previous = 0.0;
        for step in 1..=100 {
            let x = step as f64 / 100.0;
            let value = regularized_incomplete_beta(2.0, 3.0, x);
            assert!(value >= previous, "not monotone at {x}");
            previous = value;
        }
        // `I_0.5(2, 3)` is 0.6875: a closed form, so this pins the series rather
        // than only its shape.
        assert!((regularized_incomplete_beta(2.0, 3.0, 0.5) - 0.6875).abs() < 1e-12);
    }

    /// The symmetry relation the implementation branches on has to hold on both
    /// sides of the symmetry point, or the two halves describe different
    /// distributions.
    #[test]
    fn the_cdf_agrees_with_its_reflection() {
        for &(a, b) in &[(2.5_f64, 7.5_f64), (40.0, 12.0), (0.5, 0.5)] {
            for step in 1..20 {
                let x = step as f64 / 20.0;
                let direct = regularized_incomplete_beta(a, b, x);
                let reflected = 1.0 - regularized_incomplete_beta(b, a, 1.0 - x);
                assert!(
                    (direct - reflected).abs() < 1e-12,
                    "a={a} b={b} x={x}: {direct} vs {reflected}"
                );
            }
        }
    }

    /// `NormalCdf` is the standard normal CDF: `Phi(0) = 0.5`, `Phi(-1.96)` is
    /// about 0.025, and it is symmetric.
    #[test]
    fn the_normal_cdf_is_the_standard_one() {
        assert!((normal_cdf(0.0) - 0.5).abs() < 1e-15);
        assert!((normal_cdf(-1.959_963_984_540_054) - 0.025).abs() < 1e-12);
        assert!((normal_cdf(1.5) + normal_cdf(-1.5) - 1.0).abs() < 1e-15);
    }

    /// The asymptotic branch has to stay a CDF: Node switches to it purely on the
    /// shape parameters, so a `qrde` with a million samples passes through it and
    /// a value outside `[0, 1]` there would move a quantile outside the data.
    #[test]
    fn the_asymptotic_branch_stays_within_the_unit_interval() {
        let params = beta_parameters(200_000.0, 200_000.0, true);
        assert!(params.use_asymptotic_cdf);
        assert!(params.use_asymptotic_front);
        let (low, _) = regularized_incomplete_beta_with_front(&params, 0.49, false);
        let (high, _) = regularized_incomplete_beta_with_front(&params, 0.51, false);
        assert!((0.0..=1.0).contains(&low), "{low}");
        assert!((0.0..=1.0).contains(&high), "{high}");
        assert!(low < high);
    }

    /// Large shapes below the CDF threshold still take the continued fraction, but
    /// with the asymptotic *front*; the two halves have to agree closely enough
    /// that a `qrde` quantile does not jump when the threshold is crossed.
    #[test]
    fn the_asymptotic_front_matches_the_exact_one() {
        // `a * b / (a + b) = 8 * 8 / 16 = 4`, below the 25 000 CDF threshold.
        let approximate = beta_parameters(8.0, 8.0, true);
        assert!(approximate.use_asymptotic_front);
        assert!(!approximate.use_asymptotic_cdf);
        let exact = beta_parameters(8.0, 8.0, false);
        assert!(!exact.use_asymptotic_front);
        for step in 1..20 {
            let x = step as f64 / 20.0;
            let a = beta_front(&approximate, x);
            let b = beta_front(&exact, x);
            let relative = (a - b).abs() / b;
            assert!(relative < 1e-12, "x={x}: {a} vs {b} ({relative})");
        }
    }
}
