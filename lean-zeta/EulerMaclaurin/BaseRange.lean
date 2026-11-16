module

public import EulerMaclaurin.BaseCase

/-!
# The range-level `p = 0` Euler–Maclaurin identity

Summing `∫_k^{k+1} f = (1/2)(f(k+1) + f(k)) - ∫_k^{k+1} B̃_1 f'` over `k ∈ [m, n)` gives

$$\int_m^n f = \sum_{k=m}^{n-1} f(k) + \frac{f(n) - f(m)}{2} - \int_m^n \tilde B_1 f'.$$

## Main results

* `integral_eq_sum_Ico_add_half_sub` — the identity above.
-/

@[expose] public section

open scoped Interval BigOperators
open MeasureTheory intervalIntegral

noncomputable section

namespace EulerMaclaurin

variable {E : Type*} [NormedAddCommGroup E] [NormedSpace ℝ E] [CompleteSpace E]

/-- `∑_{k=m}^{n-1} (f(k+1) + f(k)) = 2∑_{k=m}^{n-1} f(k) + f(n) - f(m)`. -/
theorem sum_Ico_add_shift {f : ℕ → E} {m n : ℕ} (hmn : m ≤ n) :
    ∑ k ∈ Finset.Ico m n, (f (k + 1) + f k)
      = (2 : ℝ) • (∑ k ∈ Finset.Ico m n, f k) + (f n - f m) := by
  have h1 : ∑ k ∈ Finset.Ico m n, f (k + 1) = (∑ k ∈ Finset.Ico m n, f k) + (f n - f m) := by
    have key : ∑ k ∈ Finset.Ico m n, f (k + 1) - ∑ k ∈ Finset.Ico m n, f k = f n - f m := by
      rw [← Finset.sum_sub_distrib]
      exact Finset.sum_Ico_sub f hmn
    rw [sub_eq_iff_eq_add] at key
    rw [key, add_comm]
  rw [Finset.sum_add_distrib, h1]
  module

/-- **The `p = 0` Euler–Maclaurin identity over a range.**

`f` must be `C²` on an open set containing `[m, n]`. -/
theorem integral_eq_sum_Ico_add_half_sub {f : ℝ → E} {s : Set ℝ} (hs : IsOpen s)
    {m n : ℕ} (hmn : m ≤ n)
    (hsub : Set.Icc (m : ℝ) (n : ℝ) ⊆ s)
    (hf : ContDiffOn ℝ 2 f s) :
    ∫ x in (m : ℝ)..(n : ℝ), f x
      = ∑ k ∈ Finset.Ico m n, f (k : ℝ)
        + (1 / 2 : ℝ) • (f (n : ℝ) - f (m : ℝ))
        - ∫ x in (m : ℝ)..(n : ℝ), periodicBernoulli 1 x • iteratedDerivWithin 1 f s x := by
  -- continuity on each unit subinterval
  have hsubk : ∀ k : ℕ, m ≤ k → k < n → Set.Icc (k : ℝ) ((k : ℝ) + 1) ⊆ s := by
    intro k hk1 hk2 x hx
    exact hsub ⟨(Nat.cast_le.mpr hk1).trans hx.1, by
      have : (k : ℝ) + 1 ≤ (n : ℝ) := by
        have h : ((k : ℝ) + 1) = ((k + 1 : ℕ) : ℝ) := by push_cast; ring
        rw [h]; exact Nat.cast_le.mpr hk2
      exact hx.2.trans this⟩
  have hone : (((1 : ℕ)) : WithTop ℕ∞) ≤ ((2 : ℕ) : WithTop ℕ∞) := by
    show (((1 : ℕ) : ℕ∞) : WithTop ℕ∞) ≤ (((2 : ℕ) : ℕ∞) : WithTop ℕ∞); norm_cast
  have hcont1 : ∀ k : ℕ, m ≤ k → k < n →
      ContinuousOn (iteratedDerivWithin 1 f s) (Set.Icc (k : ℝ) ((k : ℝ) + 1)) :=
    fun k hk1 hk2 => (hf.continuousOn_iteratedDerivWithin (n := ((2:ℕ) : WithTop ℕ∞))
      (m := 1) hone hs.uniqueDiffOn).mono (hsubk k hk1 hk2)
  -- decompose the two integrals into unit-interval pieces
  have hdec1 : ∫ x in (m : ℝ)..(n : ℝ), f x
      = ∑ k ∈ Finset.Ico m n, ∫ x in (k : ℝ)..((k : ℝ) + 1), f x := by
    have := integral_periodicBernoulli_smul_eq_sum_Ico (p := 0) (s := s) (f := f) hmn
      (fun k hk1 hk2 => by rw [iteratedDerivWithin_zero]; exact (hf.continuousOn).mono (hsubk k hk1 hk2))
    simpa [periodicBernoulli_zero_smul] using this
  have hdec2 : ∫ x in (m : ℝ)..(n : ℝ),
        periodicBernoulli 1 x • iteratedDerivWithin 1 f s x
      = ∑ k ∈ Finset.Ico m n,
          ∫ x in (k : ℝ)..((k : ℝ) + 1),
            periodicBernoulli 1 x • iteratedDerivWithin 1 f s x :=
    integral_periodicBernoulli_smul_eq_sum_Ico hmn hcont1
  rw [hdec1, hdec2]
  -- replace each unit integral using the per-interval identity
  have hstep : ∀ k ∈ Finset.Ico m n,
      ∫ x in (k : ℝ)..((k : ℝ) + 1), f x
        = (1 / 2 : ℝ) • (f ((k : ℝ) + 1) + f (k : ℝ))
          - ∫ x in (k : ℝ)..((k : ℝ) + 1),
              periodicBernoulli 1 x • iteratedDerivWithin 1 f s x :=
    fun k hk => integral_unit_eq_half_add hs
      (hsubk k (Finset.mem_Ico.mp hk).1 (Finset.mem_Ico.mp hk).2) hf
  rw [Finset.sum_congr rfl hstep, Finset.sum_sub_distrib]
  -- the first sum: `∑ (1/2) • (f(k+1) + f(k)) = ∑ f + (f(n)-f(m))/2`
  rw [← Finset.smul_sum]
  have hshift : ∑ k ∈ Finset.Ico m n, (f ((k:ℝ) + 1) + f (k:ℝ))
      = (2 : ℝ) • (∑ k ∈ Finset.Ico m n, f (k:ℝ)) + (f (n:ℝ) - f (m:ℝ)) := by
    have := sum_Ico_add_shift (f := fun k : ℕ => f (k : ℝ)) (m := m) (n := n) hmn
    simpa [Nat.cast_add, Nat.cast_one] using this
  rw [hshift, smul_add, smul_smul]
  norm_num

end EulerMaclaurin
