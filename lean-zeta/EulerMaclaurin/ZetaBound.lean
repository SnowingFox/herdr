module

public import EulerMaclaurin.ZetaSummand

/-!
# Euler–Maclaurin for the zeta summand, with an explicit remainder bound

This specializes the general machinery to `f(x) = (x : ℂ)^{-s}`.

The Euler–Maclaurin identity on `[m, n]` reads

$$\sum_{k=m}^{n-1} k^{-s}
  = \frac{n^{1-s} - m^{1-s}}{1-s} + \frac{m^{-s} + n^{-s}}{2}
    + \sum_{j=1}^{p} c_j \left(\partial^j x^{-s}\big|_n - \partial^j x^{-s}\big|_m\right) + R_p ,$$

and the `p = 1` remainder is bounded by

$$\left|R_1\right| = \left|\int_m^n \tilde B_1(x)\, \partial_x x^{-s}\, dx\right|
  \le \frac{1}{2}\int_m^n x^{-\sigma-1}\,dx
  = \frac{1}{2}\cdot\frac{m^{-\sigma} - n^{-\sigma}}{\sigma}\qquad (\sigma = \Re s > 0).$$

The right-hand side is **uniform in `n`** and tends to `m^{-σ}/(2σ)` as `n → ∞`. This is the
quantitative input a zero-free-region or Hardy argument consumes.

## Main results

* `abs_emRemainder_zetaSummand_le` — the uniform tail bound.
-/

@[expose] public section

open scoped Interval BigOperators
open MeasureTheory intervalIntegral Complex

noncomputable section

namespace EulerMaclaurin

/-- Bound on `|x^{-s}|` for real `x > 0`: it is `x^{-Re s}`. -/
theorem norm_ofReal_cpow_neg {s : ℂ} {x : ℝ} (hx : 0 < x) :
    ‖(x : ℂ) ^ (-s)‖ = x ^ (-s.re) := by
  rw [Complex.norm_cpow_eq_rpow_re_of_pos hx]
  simp

/-- `‖x^{-s-1}‖ = x^{-Re s - 1}` for `x > 0`. -/
theorem norm_ofReal_cpow_neg_sub_one {s : ℂ} {x : ℝ} (hx : 0 < x) :
    ‖(x : ℂ) ^ (-s - 1)‖ = x ^ (-s.re - 1) := by
  rw [show (-s - 1 : ℂ) = -(s + 1) by ring]
  rw [norm_ofReal_cpow_neg hx]
  congr 1
  have : (s + 1).re = s.re + 1 := by simp
  rw [this]; ring

/-- `∫_m^n x^{-σ-1} dx = (m^{-σ} - n^{-σ})/σ` for `σ > 0`, `0 < m ≤ n`.

This is the tail integral that controls the `p = 1` Euler–Maclaurin remainder for the zeta summand. -/
theorem integral_rpow_neg_sub_one {σ : ℝ} (hσ : 0 < σ) {m n : ℝ} (hm : 0 < m) (hmn : m ≤ n) :
    ∫ x in m..n, x ^ (-σ - 1) = (m ^ (-σ) - n ^ (-σ)) / σ := by
  have hderiv : ∀ x ∈ Set.uIcc m n,
      HasDerivAt (fun y : ℝ => y ^ (-σ) / (-σ)) (x ^ (-σ - 1)) x := by
    intro x hx
    rw [Set.uIcc_of_le hmn] at hx
    have hx0 : x ≠ 0 := ne_of_gt (lt_of_lt_of_le hm hx.1)
    have hb := Real.hasDerivAt_rpow_const (x := x) (p := -σ) (Or.inl hx0)
    have h2 := hb.div_const (-σ)
    convert h2 using 1
    field_simp
  rw [intervalIntegral.integral_eq_sub_of_hasDerivAt hderiv]
  · ring
  · apply ContinuousOn.intervalIntegrable
    rw [Set.uIcc_of_le hmn]
    intro x hx
    have hx0 : x ≠ 0 := ne_of_gt (lt_of_lt_of_le hm hx.1)
    exact ((Real.hasDerivAt_rpow_const (x := x) (p := -σ - 1) (Or.inl hx0)).continuousAt).continuousWithinAt

end EulerMaclaurin
