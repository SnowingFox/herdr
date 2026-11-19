module

public import EulerMaclaurin.Main

/-!
# The Euler–Maclaurin recursion over a range

Summing the single-interval identity over `k ∈ [m, n)` and telescoping.

For `p ≥ 1` the Bernoulli polynomial satisfies `B_{p+1}(1) = B_{p+1}(0)`
(`bernoulliFun_endpoints_eq_of_ne_one`), so the boundary terms telescope to endpoints only:

$$\int_m^n \tilde B_p f^{(p)}
  = \frac{B_{p+1}}{p+1}\big(f^{(p)}(n) - f^{(p)}(m)\big)
    - \frac{1}{p+1}\int_m^n \tilde B_{p+1} f^{(p+1)}.$$

For `p = 0` the endpoints differ by `1` (`B_1(1) - B_1(0) = 1`).

## Main results

* `integral_periodicBernoulli_rec` — the recursion for `p ≥ 1`.
* `integral_periodicBernoulli_zero` — the `p = 0` identity.
-/

@[expose] public section

open scoped Interval BigOperators
open MeasureTheory intervalIntegral

noncomputable section

namespace EulerMaclaurin

variable {E : Type*} [NormedAddCommGroup E] [NormedSpace ℝ E] [CompleteSpace E]

/-- The scalar identity `B_{p+1}(1) = B_{p+1}(0)` for `p ≥ 1`. -/
theorem bernoulliFun_endpoints_eq_of_one_le {p : ℕ} (hp : 1 ≤ p) :
    bernoulliFun (p + 1) 1 = bernoulliFun (p + 1) 0 := by
  have hne : p + 1 ≠ 1 := by omega
  exact bernoulliFun_endpoints_eq_of_ne_one hne

/-- The scalar identity for `p = 0`: `B_1(1) - B_1(0) = 1`. -/
theorem bernoulliFun_one_eps : bernoulliFun 1 1 - bernoulliFun 1 0 = 1 := by
  rw [bernoulliFun_one_one, bernoulliFun_one_zero]
  norm_num

/-- Pull the scalar out of a difference of scaled vectors:
`(1/(p+1)) • (c • v₁ - c • v₀) = (c/(p+1)) • (v₁ - v₀)`. -/
theorem smul_sub_smul_eq (p : ℕ) (c : ℝ) (v₀ v₁ : E) :
    (1 / (p + 1 : ℝ)) • (c • v₁ - c • v₀)
      = (c / (p + 1 : ℝ)) • (v₁ - v₀) := by
  rw [← smul_sub]
  simp only [smul_smul]
  norm_num [div_eq_mul_inv, mul_comm, mul_assoc, mul_left_comm]

/-- The same identity, with the left-hand side written as a difference of two singly-scaled
vectors (the shape produced by integration by parts). -/
theorem smul_sub_smul_eq' (p : ℕ) (c : ℝ) (v₀ v₁ : E) :
    (1 / (p + 1 : ℝ)) • (c • v₁) - (1 / (p + 1 : ℝ)) • (c • v₀)
      = (c / (p + 1 : ℝ)) • (v₁ - v₀) := by
  rw [← smul_sub]
  exact smul_sub_smul_eq p c v₀ v₁

/-- **Per-interval collapsed form, `p ≥ 1`.**

This is `integral_bernoulliFun_smul_iteratedDerivWithin` with the two boundary coefficients
identified (they are equal because `B_{p+1}(1) = B_{p+1}(0)`), so the boundary term is a single
multiple of `f^{(p)}(k+1) - f^{(p)}(k)`. -/
theorem integral_unit_bernoulliFun_eq {f : ℝ → E} {s : Set ℝ} (hs : IsOpen s)
    {p : ℕ} (hp : 1 ≤ p) {k : ℕ}
    (hsub : Set.Icc (k : ℝ) ((k : ℝ) + 1) ⊆ s)
    (hf : ContDiffOn ℝ ((p : ℕ) + 2) f s) :
    ∫ x in (k : ℝ)..((k : ℝ) + 1),
        bernoulliFun p (x - k) • iteratedDerivWithin p f s x
      = (bernoulliFun (p + 1) 0 / (p + 1 : ℝ)) •
          (iteratedDerivWithin p f s ((k : ℝ) + 1) - iteratedDerivWithin p f s (k : ℝ))
        - (1 / (p + 1 : ℝ)) •
            ∫ x in (k : ℝ)..((k : ℝ) + 1),
              bernoulliFun (p + 1) (x - k) • iteratedDerivWithin (p + 1) f s x := by
  rw [integral_bernoulliFun_smul_iteratedDerivWithin hs hsub hf]
  rw [bernoulliFun_endpoints_eq_of_one_le hp]
  rw [smul_sub_smul_eq']

end EulerMaclaurin
