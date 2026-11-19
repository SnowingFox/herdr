module

public import EulerMaclaurin.ZetaBound
public import Mathlib.Analysis.SpecialFunctions.Pow.Deriv

/-!
# Smoothness of `x ↦ x^{-σ}` on `(0,∞)`

For the *real* function `x ↦ x^{-σ}` Mathlib supplies `contDiffAt_rpow_const` directly, so the
Euler–Maclaurin application to the zeta summand is immediate.

## Main results

* `contDiffOn_rpow_neg` — `C^n` on `(0,∞)`.
-/

@[expose] public section

open scoped Interval BigOperators
open MeasureTheory intervalIntegral Complex

noncomputable section

namespace EulerMaclaurin

/-- `x ↦ x^{-σ}` is `C^n` on `(0,∞)`. -/
theorem contDiffOn_rpow_neg (σ : ℝ) (n : ℕ) :
    ContDiffOn ℝ n (fun y : ℝ => y ^ (-σ)) (Set.Ioi 0) :=
  fun x hx =>
    (Real.contDiffAt_rpow_const (x := x) (p := -σ) (n := n) (Or.inl (ne_of_gt hx))).contDiffWithinAt

/-- `x ↦ x^{-σ}` is `C²` on `(0,∞)`, the order needed for the `p = 0` identity. -/
theorem contDiffOn_two_rpow_neg (σ : ℝ) :
    ContDiffOn ℝ 2 (fun y : ℝ => y ^ (-σ)) (Set.Ioi 0) :=
  contDiffOn_rpow_neg σ 2

end EulerMaclaurin
