module

public import EulerMaclaurin.Telescope

/-!
# Telescoping the single-interval step over a range

This file assembles the range-level Euler–Maclaurin recursion from the single-interval step.

## Main results

* `integral_periodicBernoulli_smul_eq_sum_Ico` — the unit-interval decomposition.
* `sum_Ico_iteratedDeriv_succ_sub` — telescoping of boundary values.
-/

@[expose] public section

open scoped Interval BigOperators
open MeasureTheory intervalIntegral

noncomputable section

namespace EulerMaclaurin

variable {E : Type*} [NormedAddCommGroup E] [NormedSpace ℝ E] [CompleteSpace E]

omit [CompleteSpace E] in
/-- A bounded 1-periodic function agrees a.e. with its polynomial representative on a unit
interval, so integrability transfers. -/
theorem intervalIntegrable_periodicBernoulli_smul_unit {f : ℝ → E} {s : Set ℝ} {p : ℕ} {k : ℕ}
    (hcont : ContinuousOn (iteratedDerivWithin p f s) (Set.Icc (k : ℝ) ((k : ℝ) + 1))) :
    IntervalIntegrable (fun x => periodicBernoulli p x • iteratedDerivWithin p f s x)
      volume (k : ℝ) ((k : ℝ) + 1) := by
  have hkle : (k : ℝ) ≤ (k : ℝ) + 1 := by linarith
  have hpoly_cont : ContinuousOn
      (fun x => bernoulliFun p (x - k) • iteratedDerivWithin p f s x)
      (Set.uIcc (k : ℝ) ((k : ℝ) + 1)) := by
    rw [Set.uIcc_of_le hkle]
    exact (((continuous_bernoulliFun p).comp
      (continuous_id.sub continuous_const)).continuousOn).smul hcont
  refine IntervalIntegrable.congr_ae hpoly_cont.intervalIntegrable ?_
  have hmem : ∀ᵐ x : ℝ ∂(volume.restrict (Ι (k : ℝ) ((k : ℝ) + 1))),
      x ∈ Ι (k : ℝ) ((k : ℝ) + 1) := ae_restrict_mem measurableSet_Ioc
  have h1 : ∀ᵐ x : ℝ ∂(volume.restrict (Ι (k : ℝ) ((k : ℝ) + 1))), x ≠ (k : ℝ) :=
    Measure.ae_ne _ _
  have h2 : ∀ᵐ x : ℝ ∂(volume.restrict (Ι (k : ℝ) ((k : ℝ) + 1))), x ≠ ((k : ℝ) + 1) :=
    Measure.ae_ne _ _
  filter_upwards [hmem, h1, h2] with x hxmem hx1 hx2
  rw [Set.uIoc_of_le hkle] at hxmem
  exact (periodicBernoulli_smul_eq_on_Ioo p
    ⟨hxmem.1, lt_of_le_of_ne hxmem.2 hx2⟩).symm

/-- Decompose the integral of `B̃_p • f^{(p)}` over `[m,n]` into its unit-interval pieces. -/
theorem integral_periodicBernoulli_smul_eq_sum_Ico {f : ℝ → E} {s : Set ℝ} {p : ℕ} {m n : ℕ}
    (hmn : m ≤ n)
    (hcont : ∀ k : ℕ, m ≤ k → k < n →
      ContinuousOn (iteratedDerivWithin p f s) (Set.Icc (k : ℝ) ((k : ℝ) + 1))) :
    ∫ x in (m : ℝ)..(n : ℝ), periodicBernoulli p x • iteratedDerivWithin p f s x
      = ∑ k ∈ Finset.Ico m n,
          ∫ x in (k : ℝ)..((k : ℝ) + 1), periodicBernoulli p x • iteratedDerivWithin p f s x := by
  have hint : ∀ k : ℕ, m ≤ k → k < n →
      IntervalIntegrable (fun x => periodicBernoulli p x • iteratedDerivWithin p f s x)
        volume (k : ℝ) ((k : ℝ) + 1) :=
    fun k h1 h2 => intervalIntegrable_periodicBernoulli_smul_unit (hcont k h1 h2)
  have := sum_integral_adjacent_intervals_Ico (μ := volume)
    (f := fun x => periodicBernoulli p x • iteratedDerivWithin p f s x)
    (a := fun k : ℕ => (k : ℝ)) (m := m) (n := n) hmn ?_
  · rw [← this]
    apply Finset.sum_congr rfl
    intro k _
    norm_num
  · intro k hk
    have := hint k hk.1 hk.2
    simpa [Nat.cast_add, Nat.cast_one] using this

omit [CompleteSpace E] in
/-- **Telescoping of the boundary values** of `f^{(p)}` over the range. -/
theorem sum_Ico_iteratedDeriv_succ_sub {f : ℝ → E} {s : Set ℝ} {p : ℕ} {m n : ℕ} (hmn : m ≤ n) :
    ∑ k ∈ Finset.Ico m n,
        (iteratedDerivWithin p f s ((k : ℝ) + 1) - iteratedDerivWithin p f s (k : ℝ))
      = iteratedDerivWithin p f s (n : ℝ) - iteratedDerivWithin p f s (m : ℝ) := by
  have key : ∀ k : ℕ, (iteratedDerivWithin p f s ((k : ℝ) + 1) - iteratedDerivWithin p f s (k : ℝ))
      = ((fun j : ℕ => iteratedDerivWithin p f s (j : ℝ)) (k + 1)
          - (fun j : ℕ => iteratedDerivWithin p f s (j : ℝ)) k) := by
    intro k
    push_cast
    ring
  simp_rw [key]
  exact Finset.sum_Ico_sub (fun j : ℕ => iteratedDerivWithin p f s (j : ℝ)) hmn

/-- Decomposition of `B̃_p · g` into unit intervals, independent of any `f`. -/
theorem integral_periodicBernoulli_mul_eq_sum_Ico' {g : ℝ → ℝ} {p : ℕ} {m n : ℕ}
    (hmn : m ≤ n)
    (hcont : ∀ k : ℕ, m ≤ k → k < n →
      ContinuousOn g (Set.Icc (k : ℝ) ((k : ℝ) + 1))) :
    ∫ x in (m : ℝ)..(n : ℝ), periodicBernoulli p x * g x
      = ∑ k ∈ Finset.Ico m n,
          ∫ x in (k : ℝ)..((k : ℝ) + 1), periodicBernoulli p x * g x := by
  have hint : ∀ k : ℕ, m ≤ k → k < n →
      IntervalIntegrable (fun x => periodicBernoulli p x * g x) volume (k : ℝ) ((k : ℝ) + 1) := by
    intro k hk1 hk2
    have hkle : (k : ℝ) ≤ (k : ℝ) + 1 := by linarith
    have hpoly : ContinuousOn (fun x => bernoulliFun p (x - k) * g x)
        (Set.uIcc (k : ℝ) ((k : ℝ) + 1)) := by
      rw [Set.uIcc_of_le hkle]
      exact (((continuous_bernoulliFun p).comp
        (continuous_id.sub continuous_const)).continuousOn).mul (hcont k hk1 hk2)
    refine IntervalIntegrable.congr_ae hpoly.intervalIntegrable ?_
    have hmem : ∀ᵐ x : ℝ ∂(volume.restrict (Ι (k : ℝ) ((k : ℝ) + 1))),
        x ∈ Ι (k : ℝ) ((k : ℝ) + 1) := ae_restrict_mem measurableSet_Ioc
    have h1 : ∀ᵐ x : ℝ ∂(volume.restrict (Ι (k : ℝ) ((k : ℝ) + 1))), x ≠ ((k : ℝ) + 1) :=
      Measure.ae_ne _ _
    filter_upwards [hmem, h1] with x hxmem hx1
    rw [Set.uIoc_of_le hkle] at hxmem
    rw [periodicBernoulli_eq_on_Ioo p ⟨hxmem.1, lt_of_le_of_ne hxmem.2 hx1⟩]
  have hkey := sum_integral_adjacent_intervals_Ico (μ := volume)
    (f := fun x => periodicBernoulli p x * g x)
    (a := fun k : ℕ => (k : ℝ)) hmn
    (fun k hk => by
      have := hint k hk.1 hk.2
      simpa [Nat.cast_add, Nat.cast_one] using this)
  rw [← hkey]
  apply Finset.sum_congr rfl
  intro k _
  norm_num

end EulerMaclaurin
