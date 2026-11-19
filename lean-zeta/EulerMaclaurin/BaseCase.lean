module

public import EulerMaclaurin.Recursion2

/-!
# The `p = 0` Euler–Maclaurin step

For `p = 0` the periodic Bernoulli function `B̃_0 ≡ 1`, but the endpoint values
`B_1(1) = 1/2` and `B_1(0) = -1/2` **differ**, so the boundary terms do not telescope. Instead,
summing the per-interval identity

`∫_k^{k+1} f = (1/2)(f(k+1) + f(k)) - ∫_k^{k+1} B̃_1 f'`

over `k ∈ [m, n)` and using `∑_{k=m}^{n-1} f(k+1) = ∑_{k=m}^{n-1} f(k) + f(n) - f(m)` gives

`∫_m^n f = ∑_{k=m}^{n-1} f(k) + (f(n) - f(m))/2 - ∫_m^n B̃_1 f'`.

## Main results

* `integral_unit_eq_half_add` — the single-interval `p = 0` identity.
* `integral_eq_sum_Ico_add_half_sub` — the range-level identity above.
-/

@[expose] public section

open scoped Interval BigOperators
open MeasureTheory intervalIntegral

noncomputable section

namespace EulerMaclaurin

variable {E : Type*} [NormedAddCommGroup E] [NormedSpace ℝ E] [CompleteSpace E]

/-- The periodic Bernoulli function `B̃_0` is identically `1`. -/
theorem periodicBernoulli_zero_apply (x : ℝ) : periodicBernoulli 0 x = 1 := by
  simp [periodicBernoulli]

/-- The `p = 0` integrand is just `f`. -/
theorem periodicBernoulli_zero_smul {f : ℝ → E} {s : Set ℝ} (x : ℝ) :
    periodicBernoulli 0 x • iteratedDerivWithin 0 f s x = f x := by
  simp [periodicBernoulli, iteratedDerivWithin_zero]

/-- On a unit interval, the `p = 0` identity reads
`∫_k^{k+1} f = (1/2)(f(k+1) + f(k)) - ∫_k^{k+1} B̃_1 f'`. -/
theorem integral_unit_eq_half_add {f : ℝ → E} {s : Set ℝ} (hs : IsOpen s) {k : ℕ}
    (hsub : Set.Icc (k : ℝ) ((k : ℝ) + 1) ⊆ s)
    (hf : ContDiffOn ℝ 2 f s) :
    ∫ x in (k : ℝ)..((k : ℝ) + 1), f x
      = (1 / 2 : ℝ) • (f ((k : ℝ) + 1) + f (k : ℝ))
        - ∫ x in (k : ℝ)..((k : ℝ) + 1),
            periodicBernoulli 1 x • iteratedDerivWithin 1 f s x := by
  have hf' : ContDiffOn ℝ ((0 : ℕ) + 2) f s := by simpa using hf
  have h0 := integral_bernoulliFun_smul_iteratedDerivWithin (E := E) hs (p := 0) (k := k)
    hsub hf'
  -- `h0 : ∫ B_0(x-k) • f = (1/1) • (B_1(1) • f(k+1) - B_1(0) • f(k) - ∫ B_1(x-k) • f')`
  simp only [iteratedDerivWithin_zero] at h0
  rw [bernoulliFun_one_zero, bernoulliFun_one_one] at h0
  -- replace the polynomial integrals by the periodic ones
  rw [← integral_periodicBernoulli_smul (p := 0) k (fun x => f x),
      ← integral_periodicBernoulli_smul (p := 1) k
        (fun x => iteratedDerivWithin 1 f s x)] at h0
  -- reconcile `∫ B_0(x-k) • f` with `∫ f`
  have hL : ∫ x in (k : ℝ)..((k : ℝ) + 1), periodicBernoulli 0 x • f x
      = ∫ x in (k : ℝ)..((k : ℝ) + 1), f x := by
    apply intervalIntegral.integral_congr
    intro x _
    simp
  rw [hL] at h0
  refine h0.trans ?_
  simp only [Nat.cast_zero, zero_add, div_one, one_mul, smul_smul, smul_add]
  norm_num

end EulerMaclaurin
