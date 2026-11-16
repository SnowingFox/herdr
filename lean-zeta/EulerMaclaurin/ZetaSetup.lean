module

public import EulerMaclaurin.SumIntegral
public import Mathlib.NumberTheory.LSeries.RiemannZeta
public import Mathlib.Analysis.SpecialFunctions.Pow.Deriv

/-!
# Euler–Maclaurin for `x ↦ x^{-s}` : the zeta continuation infrastructure

This file specializes the Euler–Maclaurin machinery to the standard integrand `x ↦ (x : ℂ)^{-s}`.

## Main results

* `hasDerivAt_ofReal_cpow_neg` — derivative of `x ↦ x^{-s}` for `x > 0`.
* `contDiffOn_ofReal_cpow_neg` — `C^n` smoothness of the same on `(0, ∞)`.
-/

@[expose] public section

open scoped Interval BigOperators
open MeasureTheory intervalIntegral Complex

noncomputable section

namespace EulerMaclaurin

/-- For `x ≠ 0`, the function `x ↦ (x : ℂ)^(-s)` has derivative `(-s) * x^(-s-1)`. -/
theorem hasDerivAt_ofReal_cpow_neg {s : ℂ} (hs : s ≠ 0) {x : ℝ} (hx : x ≠ 0) :
    HasDerivAt (fun y : ℝ => (y : ℂ) ^ (-s)) ((-s) * (x : ℂ) ^ (-s - 1)) x :=
  hasDerivAt_ofReal_cpow_const hx (neg_ne_zero.mpr hs)

/-- The derivative of `x ↦ x^{-s}` is a constant times `x^{-((s+1))}`. -/
theorem deriv_ofReal_cpow_neg {s : ℂ} (hs : s ≠ 0) {x : ℝ} (hx : x ≠ 0) :
    deriv (fun y : ℝ => (y : ℂ) ^ (-s)) x = (-s) * (x : ℂ) ^ (-(s + 1)) := by
  rw [(hasDerivAt_ofReal_cpow_neg hs hx).deriv]
  congr 2
  ring

/-- `x ↦ (x : ℂ)^{-s}` is differentiable on `(0, ∞)`. -/
theorem differentiableOn_ofReal_cpow_neg (s : ℂ) (hs : s ≠ 0) :
    DifferentiableOn ℝ (fun y : ℝ => (y : ℂ) ^ (-s)) (Set.Ioi 0) :=
  fun x hx => (hasDerivAt_ofReal_cpow_neg hs (ne_of_gt hx)).differentiableAt.differentiableWithinAt

end EulerMaclaurin
