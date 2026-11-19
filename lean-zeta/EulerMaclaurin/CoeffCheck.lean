module

public import EulerMaclaurin.GeneralRemainder

open scoped Interval BigOperators
open MeasureTheory intervalIntegral

noncomputable section

namespace EulerMaclaurin

/-!
# Coefficient sanity checks

These verify that the symbolic coefficients `emCoeff` and `emRemCoeff` carry the classical numerical
values, cross-checked against Apostol, *Introduction to Analytic Number Theory*, Theorem 3.1.

With Mathlib's convention `B₁ = -1/2, B₂ = 1/6, B₃ = 0, B₄ = -1/30`:

| `j` | `emCoeff j = (-1)^j B_{j+1}/(j+1)!` | expected |
|---|---|---|
| 1 | `-B₂/2!` | `-1/12` |
| 2 | `+B₃/3!` | `0` |
| 3 | `-B₄/4!` | `+1/720` |

| `p` | `emRemCoeff p = (-1)^{p+1}/(p+1)!` | expected |
|---|---|---|
| 0 | `-1` | `-1` |
| 1 | `+1/2` | `1/2` |
| 3 | `+1/24` | `1/24` (in absolute value) |
-/

-- Apostol's `B₁` is `+1/2`; Mathlib's is `-1/2`, hence the sign in `emCoeff`.
example : emCoeff 1 = -1 / 12 := by
  simp [emCoeff, bernoulli_two]
  norm_num

example : emCoeff 2 = 0 := by
  simp [emCoeff, bernoulli_eq_zero_of_odd (n := 3) (by decide) (by norm_num)]

example : emCoeff 3 = 1 / 720 := by
  have h4 : bernoulli 4 = -1 / 30 := by
    rw [bernoulli_eq_bernoulli'_of_ne_one (by norm_num : (4:ℕ) ≠ 1), bernoulli'_four]
  simp only [emCoeff, h4]
  norm_num

example : emRemCoeff 0 = -1 := by simp [emRemCoeff]
example : emRemCoeff 1 = 1 / 2 := by simp [emRemCoeff]
example : |emRemCoeff 3| = 1 / 24 := by
  rw [abs_emRemCoeff]; norm_num

end EulerMaclaurin
