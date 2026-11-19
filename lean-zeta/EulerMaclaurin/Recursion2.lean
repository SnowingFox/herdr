module

public import EulerMaclaurin.Recursion

/-!
# Euler–Maclaurin recursion at the level of a range

This file takes the per-interval collapsed identity and sums it over `k ∈ [m, n)`.

## Main results

* `integral_periodicBernoulli_rec` — the recursion for `p ≥ 1`.
-/

@[expose] public section

open scoped Interval BigOperators
open MeasureTheory intervalIntegral

noncomputable section

namespace EulerMaclaurin

variable {E : Type*} [NormedAddCommGroup E] [NormedSpace ℝ E] [CompleteSpace E]

/-- **Euler–Maclaurin recursion over a range, `p ≥ 1`.**

`f` must be `C^{p+2}` on an open set containing `[m, n]`. -/
theorem integral_periodicBernoulli_rec {f : ℝ → E} {s : Set ℝ} (hs : IsOpen s)
    {p : ℕ} (hp : 1 ≤ p) {m n : ℕ} (hmn : m ≤ n)
    (hsub : Set.Icc (m : ℝ) (n : ℝ) ⊆ s)
    (hf : ContDiffOn ℝ ((p : ℕ) + 2) f s) :
    ∫ x in (m : ℝ)..(n : ℝ), periodicBernoulli p x • iteratedDerivWithin p f s x
      = (bernoulliFun (p + 1) 0 / (p + 1 : ℝ)) •
            (iteratedDerivWithin p f s (n : ℝ) - iteratedDerivWithin p f s (m : ℝ))
        - (1 / (p + 1 : ℝ)) •
            ∫ x in (m : ℝ)..(n : ℝ),
              periodicBernoulli (p + 1) x • iteratedDerivWithin (p + 1) f s x := by
  -- continuity of the needed derivatives on every unit subinterval
  have hple : ((p : ℕ) : WithTop ℕ∞) ≤ (((p + 2 : ℕ)) : WithTop ℕ∞) := by
    show ((p : ℕ∞) : WithTop ℕ∞) ≤ (((p + 2 : ℕ) : ℕ∞) : WithTop ℕ∞); norm_cast; omega
  have hp1le : (((p + 1 : ℕ)) : WithTop ℕ∞) ≤ (((p + 2 : ℕ)) : WithTop ℕ∞) := by
    show (((p + 1 : ℕ) : ℕ∞) : WithTop ℕ∞) ≤ (((p + 2 : ℕ) : ℕ∞) : WithTop ℕ∞); norm_cast; omega
  -- each unit interval sits inside `s`
  have hsubk : ∀ k : ℕ, m ≤ k → k < n → Set.Icc (k : ℝ) ((k : ℝ) + 1) ⊆ s := by
    intro k hk1 hk2 x hx
    apply hsub
    constructor
    · exact (Nat.cast_le.mpr hk1).trans hx.1
    · have : (k : ℝ) + 1 ≤ (n : ℝ) := by
        have : ((k : ℝ) + 1) = ((k + 1 : ℕ) : ℝ) := by push_cast; ring
        rw [this]
        exact Nat.cast_le.mpr hk2
      exact hx.2.trans this
  -- rewrite the two integrals as sums of unit-interval integrals
  have hcontp : ∀ k : ℕ, m ≤ k → k < n →
      ContinuousOn (iteratedDerivWithin p f s) (Set.Icc (k : ℝ) ((k : ℝ) + 1)) :=
    fun k hk1 hk2 => (hf.continuousOn_iteratedDerivWithin (n := ((p+2:ℕ) : WithTop ℕ∞))
      (m := p) hple hs.uniqueDiffOn).mono (hsubk k hk1 hk2)
  have hcontp1 : ∀ k : ℕ, m ≤ k → k < n →
      ContinuousOn (iteratedDerivWithin (p + 1) f s) (Set.Icc (k : ℝ) ((k : ℝ) + 1)) :=
    fun k hk1 hk2 => (hf.continuousOn_iteratedDerivWithin (n := ((p+2:ℕ) : WithTop ℕ∞))
      (m := p+1) hp1le hs.uniqueDiffOn).mono (hsubk k hk1 hk2)
  rw [integral_periodicBernoulli_smul_eq_sum_Ico hmn hcontp,
      integral_periodicBernoulli_smul_eq_sum_Ico hmn hcontp1]
  -- replace each unit integral by the collapsed polynomial form
  have hstep : ∀ k : ℕ, m ≤ k → k < n →
      ∫ x in (k : ℝ)..((k : ℝ) + 1), periodicBernoulli p x • iteratedDerivWithin p f s x
        = (bernoulliFun (p + 1) 0 / (p + 1 : ℝ)) •
            (iteratedDerivWithin p f s ((k : ℝ) + 1) - iteratedDerivWithin p f s (k : ℝ))
          - (1 / (p + 1 : ℝ)) •
              ∫ x in (k : ℝ)..((k : ℝ) + 1),
                periodicBernoulli (p + 1) x • iteratedDerivWithin (p + 1) f s x := by
    intro k hk1 hk2
    rw [integral_periodicBernoulli_smul p k (fun x => iteratedDerivWithin p f s x),
        integral_periodicBernoulli_smul (p + 1) k (fun x => iteratedDerivWithin (p + 1) f s x),
        integral_unit_bernoulliFun_eq hs hp (hsubk k hk1 hk2) hf]
  rw [Finset.sum_congr rfl (fun k hk => hstep k (Finset.mem_Ico.mp hk).1 (Finset.mem_Ico.mp hk).2)]
  rw [Finset.sum_sub_distrib]
  -- the boundary sum telescopes, and the integral sum is already in recombined form
  rw [← Finset.smul_sum, ← Finset.smul_sum]
  rw [sum_Ico_iteratedDeriv_succ_sub hmn]

end EulerMaclaurin
