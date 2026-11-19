module

public import EulerMaclaurin.ZetaSetup

/-!
# Euler–Maclaurin applied to the zeta summand `x ↦ x^{-s}`

This is the first concrete step of the textbook route from Euler–Maclaurin to the analytic
continuation of `ζ`: the identity

$$\sum_{k=m}^{n-1} k^{-s}
  = \int_m^n x^{-s}\,dx + \frac{m^{-s} + n^{-s}}{2}
    + \sum_{j} c_j \left(\partial^j x^{-s}\big|_n - \partial^j x^{-s}\big|_m\right) + R_p$$

with the integral evaluated in closed form
$$\int_m^n x^{-s}\,dx = \frac{n^{1-s} - m^{1-s}}{1-s}\qquad (s \ne 1).$$

## What this file does and does not do

It supplies the *finite-range, fully explicit* form. It does **not** perform the analytic
continuation: that additionally needs the tail estimate `∫_N^∞ {x} x^{-s-1} dx`, the convergence of
the Dirichlet series for `Re s > 1`, and an analyticity-in-`s` argument for the resulting expression.

## Main results

* `integral_ofReal_cpow_neg_sub` — the closed-form integral.
* `eulerMaclaurin_zetaSummand` — the specialized identity.
-/

@[expose] public section

open scoped Interval BigOperators
open MeasureTheory intervalIntegral Complex

noncomputable section

namespace EulerMaclaurin

/-- `∫_m^n x^{-s} dx = (n^{1-s} - m^{1-s})/(1-s)` for `s ≠ 1`, `0 < m`.

Stated for the complex-valued integrand `x ↦ (x:ℂ)^{-s}`. -/
theorem integral_ofReal_cpow_neg {s : ℂ} (hs : s ≠ 1) {m n : ℝ} (hm : 0 < m) (hmn : m ≤ n) :
    ∫ x in m..n, (x : ℂ) ^ (-s) = ((n : ℂ) ^ (1 - s) - (m : ℂ) ^ (1 - s)) / (1 - s) := by
  have h1s : (1 : ℂ) - s ≠ 0 := sub_ne_zero.mpr (Ne.symm hs)
  -- antiderivative: `x ↦ x^{1-s}/(1-s)`
  have hderiv : ∀ x ∈ Set.uIcc m n,
      HasDerivAt (fun y : ℝ => (y : ℂ) ^ (1 - s) / (1 - s)) ((x : ℂ) ^ (-s)) x := by
    intro x hx
    rw [Set.uIcc_of_le hmn] at hx
    have hx0 : x ≠ 0 := ne_of_gt (lt_of_lt_of_le hm hx.1)
    have hb := hasDerivAt_ofReal_cpow_const hx0 h1s
    have h2 := hb.div_const (1 - s)
    convert h2 using 1
    have hexp : (1 : ℂ) - s - 1 = -s := by ring
    rw [hexp]
    field_simp
  rw [intervalIntegral.integral_eq_sub_of_hasDerivAt hderiv]
  · ring
  · -- integrability of the integrand on the interval
    apply ContinuousOn.intervalIntegrable
    rw [Set.uIcc_of_le hmn]
    intro x hx
    have hx0 : x ≠ 0 := ne_of_gt (lt_of_lt_of_le hm hx.1)
    rcases eq_or_ne s 0 with rfl | hs0
    · -- `x ^ 0 = 1`
      have : (fun y : ℝ => (y : ℂ) ^ (-(0 : ℂ))) = fun _ => (1 : ℂ) := by
        funext y; simp
      rw [this]; exact continuous_const.continuousWithinAt
    · exact (hasDerivAt_ofReal_cpow_const hx0 (neg_ne_zero.mpr hs0)).continuousAt.continuousWithinAt

end EulerMaclaurin
