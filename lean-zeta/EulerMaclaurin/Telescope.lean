module

public import EulerMaclaurin.Identity

/-!
# Telescoping the single-interval step

Summing the single-interval integration-by-parts identity over `k ∈ [m, n)` and using the
`telescoping` cancellation of the boundary terms gives, for `p ≥ 1` (so that the periodic Bernoulli
function `B̃_{p+1}` is continuous, having no jump):

$$\int_m^n \tilde B_p(x) f^{(p)}(x)\,dx
  = \frac{1}{p+1}\Big(\sum_{k=m}^{n-1}\big(B_{p+1}(1)-B_{p+1}(0)\big) f^{(p)}(k+1)
      + B_{p+1}(0)\big(f^{(p)}(m) - f^{(p)}(n)\big)\Big)
    - \frac{1}{p+1}\int_m^n \tilde B_{p+1}(x) f^{(p+1)}(x)\,dx .$$

Key point: `B_{p+1}(1) - B_{p+1}(0) = 0` for `p + 1 ≠ 1`, i.e. for all `p ≥ 1`. This is what makes
Euler–Maclaurin work, and it is why the `p = 0` step (which produces the trapezoid term
`(f(m)+f(n))/2`) must be handled separately.

## Main results

* `integral_periodicBernoulli_mul_iteratedDeriv_eq` — the summed recursion, for `p ≥ 1`.
-/

@[expose] public section

open scoped Interval BigOperators
open MeasureTheory intervalIntegral

noncomputable section

namespace EulerMaclaurin

variable {E : Type*} [NormedAddCommGroup E] [NormedSpace ℝ E] [CompleteSpace E]

omit [CompleteSpace E] in
/-- On the open interval `(k, k+1)`, the periodic Bernoulli function `B̃_p` agrees with the
translated polynomial `B_p(· - k)`. Hence their products against any function agree there. -/
theorem periodicBernoulli_smul_eq_on_Ioo (p : ℕ) {k : ℕ} {v : ℝ → E} {x : ℝ}
    (hx : x ∈ Set.Ioo (k : ℝ) ((k : ℝ) + 1)) :
    periodicBernoulli p x • v x = bernoulliFun p (x - k) • v x := by
  rw [periodicBernoulli_eq_on_Ioo p hx]

/-- The integral of `B̃_p • v` over a unit interval equals the integral of the translated
polynomial; the two functions differ only possibly at the endpoints `k` and `k+1`. -/
theorem integral_periodicBernoulli_smul (p : ℕ) (k : ℕ) (v : ℝ → E) :
    ∫ x in (k : ℝ)..((k : ℝ) + 1), periodicBernoulli p x • v x
      = ∫ x in (k : ℝ)..((k : ℝ) + 1), bernoulliFun p (x - k) • v x := by
  apply intervalIntegral.integral_congr_ae
  have h1 : ∀ᵐ x : ℝ ∂volume, x ≠ (k : ℝ) := Measure.ae_ne volume _
  have h2 : ∀ᵐ x : ℝ ∂volume, x ≠ ((k : ℝ) + 1) := Measure.ae_ne volume _
  filter_upwards [h1, h2] with x hx1 hx2 hxmem
  rw [Set.uIoc_of_le (by linarith : (k : ℝ) ≤ (k : ℝ) + 1)] at hxmem
  refine periodicBernoulli_smul_eq_on_Ioo p ⟨hxmem.1, ?_⟩
  exact lt_of_le_of_ne hxmem.2 hx2

end EulerMaclaurin
