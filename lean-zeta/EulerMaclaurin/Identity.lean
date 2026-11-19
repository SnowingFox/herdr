module

public import EulerMaclaurin.PeriodicBernoulli

/-!
# The single-interval Euler–Maclaurin step

This file establishes the integration-by-parts recursion on one unit interval `[k, k+1]` that drives
the whole Euler–Maclaurin machine:

$$\int_k^{k+1} B_p(x-k)\, f^{(p)}(x)\,dx
  = \frac{1}{p+1}\Big(B_{p+1}(1) f^{(p)}(k+1) - B_{p+1}(0) f^{(p)}(k)
    - \int_k^{k+1} B_{p+1}(x-k)\, f^{(p+1)}(x)\,dx\Big).$$

## Main results

* `integral_bernoulliFun_smul_iteratedDerivWithin` — the identity above, for normed-space valued `f`.
-/

@[expose] public section

open scoped Interval BigOperators
open MeasureTheory intervalIntegral

noncomputable section

namespace EulerMaclaurin

variable {E : Type*} [NormedAddCommGroup E] [NormedSpace ℝ E] [CompleteSpace E]

/-- Antiderivative of `B_p(· - k)`: it is `B_{p+1}(· - k) / (p+1)`. -/
theorem hasDerivAt_antideriv_bernoulliFun (p k : ℕ) (x : ℝ) :
    HasDerivAt (fun y : ℝ => (1 / (p + 1 : ℝ)) • bernoulliFun (p + 1) (y - k))
      (bernoulliFun p (x - k)) x := by
  have h := hasDerivAt_bernoulliFun_sub (p + 1) k x
  have hp1 : (p + 1 : ℝ) ≠ 0 := by positivity
  have h2 := h.const_smul (1 / (p + 1 : ℝ))
  simp only [Nat.add_sub_cancel, smul_eq_mul, Nat.cast_add, Nat.cast_one] at h2 ⊢
  convert h2 using 1
  field_simp

omit [CompleteSpace E] in
/-- The scalar can be pulled out of the integral of a `B_{p+1}(·-k) • v`. -/
theorem integral_smul_bernoulliFun_smul (p k : ℕ) (v : ℝ → E) :
    ∫ x in (k : ℝ)..((k : ℝ) + 1),
        ((1 / (p + 1 : ℝ)) • bernoulliFun (p + 1) (x - k)) • v x
      = (1 / (p + 1 : ℝ)) •
          ∫ x in (k : ℝ)..((k : ℝ) + 1), bernoulliFun (p + 1) (x - k) • v x := by
  rw [← intervalIntegral.integral_smul]
  apply intervalIntegral.integral_congr
  intro x _
  simp only [smul_assoc]

/-- **Single-interval Euler–Maclaurin step** (integration by parts).

Requires `f` to be `C^{p+2}` on an open set containing `[k, k+1]`, so that both `f^{(p)}` and
`f^{(p+1)}` are continuous there and the interval integrals exist.

The scalars are left distributed over the boundary terms; this is exactly the form produced by
`integral_smul_deriv_eq_deriv_smul_of_hasDerivAt` and is the form consumed by the telescoping sum
over unit intervals. -/
theorem integral_bernoulliFun_smul_iteratedDerivWithin
    {f : ℝ → E} {s : Set ℝ} (hs : IsOpen s) {p : ℕ} {k : ℕ}
    (hsub : Set.Icc (k : ℝ) ((k : ℝ) + 1) ⊆ s)
    (hf : ContDiffOn ℝ ((p : ℕ) + 2) f s) :
    ∫ x in (k : ℝ)..((k : ℝ) + 1),
        bernoulliFun p (x - k) • iteratedDerivWithin p f s x
      = (1 / (p + 1 : ℝ)) • (bernoulliFun (p + 1) 1 • iteratedDerivWithin p f s ((k : ℝ) + 1))
        - (1 / (p + 1 : ℝ)) • (bernoulliFun (p + 1) 0 • iteratedDerivWithin p f s (k : ℝ))
        - (1 / (p + 1 : ℝ)) •
            ∫ x in (k : ℝ)..((k : ℝ) + 1),
                bernoulliFun (p + 1) (x - k) • iteratedDerivWithin (p + 1) f s x := by
  have hk1 : (k : ℝ) ≤ (k : ℝ) + 1 := by linarith
  have hu_cont : ContinuousOn (fun y : ℝ => (1 / (p + 1 : ℝ)) • bernoulliFun (p + 1) (y - k))
      [[(k : ℝ), (k : ℝ) + 1]] := by
    have hc : Continuous (fun y : ℝ => bernoulliFun (p + 1) (y - k)) :=
      (continuous_bernoulliFun (p+1)).comp (continuous_id.sub continuous_const)
    exact (hc.const_smul (1 / (p + 1 : ℝ))).continuousOn
  have hple : ((p : ℕ) : WithTop ℕ∞) ≤ (((p + 2 : ℕ)) : WithTop ℕ∞) := by
    show ((p : ℕ∞) : WithTop ℕ∞) ≤ (((p + 2 : ℕ) : ℕ∞) : WithTop ℕ∞); norm_cast; omega
  have hplt : ((p : ℕ) : WithTop ℕ∞) < (((p + 2 : ℕ)) : WithTop ℕ∞) := by
    show ((p : ℕ∞) : WithTop ℕ∞) < (((p + 2 : ℕ) : ℕ∞) : WithTop ℕ∞); norm_cast; omega
  have hp1le : (((p + 1 : ℕ)) : WithTop ℕ∞) ≤ (((p + 2 : ℕ)) : WithTop ℕ∞) := by
    show (((p + 1 : ℕ) : ℕ∞) : WithTop ℕ∞) ≤ (((p + 2 : ℕ) : ℕ∞) : WithTop ℕ∞); norm_cast; omega
  have hv_cont : ContinuousOn (iteratedDerivWithin p f s) [[(k : ℝ), (k : ℝ) + 1]] := by
    refine (hf.continuousOn_iteratedDerivWithin (n := ((p+2:ℕ) : WithTop ℕ∞)) (m := p)
      hple hs.uniqueDiffOn).mono ?_
    rw [Set.uIcc_of_le hk1]
    exact hsub
  have hu_deriv : ∀ x ∈ Set.Ioo (min (k:ℝ) ((k:ℝ)+1)) (max (k:ℝ) ((k:ℝ)+1)),
      HasDerivAt (fun y : ℝ => (1 / (p + 1 : ℝ)) • bernoulliFun (p + 1) (y - k))
        (bernoulliFun p (x - k)) x := fun x _ => hasDerivAt_antideriv_bernoulliFun p k x
  have hv_deriv : ∀ x ∈ Set.Ioo (min (k:ℝ) ((k:ℝ)+1)) (max (k:ℝ) ((k:ℝ)+1)),
      HasDerivAt (iteratedDerivWithin p f s) (iteratedDerivWithin (p + 1) f s x) x := by
    intro x hx
    rw [min_eq_left hk1, max_eq_right hk1] at hx
    have hxs : x ∈ s := hsub ⟨hx.1.le, hx.2.le⟩
    have hdiff : DifferentiableAt ℝ (iteratedDerivWithin p f s) x :=
      (hf.differentiableOn_iteratedDerivWithin (n := ((p + 2 : ℕ) : WithTop ℕ∞)) (m := p)
        hplt hs.uniqueDiffOn).differentiableAt (hs.mem_nhds hxs)
    have hderiv : iteratedDerivWithin (p + 1) f s x = deriv (iteratedDerivWithin p f s) x := by
      rw [iteratedDerivWithin_succ]
      exact derivWithin_of_mem_nhds (hs.mem_nhds hxs)
    rw [hderiv]
    exact hdiff.hasDerivAt
  have hu'_int : IntervalIntegrable (fun x => bernoulliFun p (x - k)) volume (k : ℝ) ((k : ℝ) + 1) := by
    apply Continuous.intervalIntegrable
    exact (continuous_bernoulliFun p).comp (continuous_id.sub continuous_const)
  have hv'_int : IntervalIntegrable (iteratedDerivWithin (p + 1) f s) volume (k : ℝ) ((k : ℝ) + 1) := by
    apply ContinuousOn.intervalIntegrable
    rw [Set.uIcc_of_le hk1]
    exact (hf.continuousOn_iteratedDerivWithin (n := ((p+2:ℕ) : WithTop ℕ∞)) (m := p+1)
      hp1le hs.uniqueDiffOn).mono hsub
  have hIBP := integral_smul_deriv_eq_deriv_smul_of_hasDerivAt hu_cont hv_cont
    hu_deriv hv_deriv hu'_int hv'_int
  have hval₁ : ((k : ℝ) + 1 - k) = 1 := by ring
  have hval₀ : ((k : ℝ) - k) = 0 := by ring
  rw [hval₁, hval₀, integral_smul_bernoulliFun_smul] at hIBP
  -- hIBP now: (1/(p+1)) • ∫ B_{p+1} • f^{(p+1)} = B̃ - ∫ B_p • f^{(p)}
  -- where B̃ = ((1/(p+1)) • B_{p+1}(1)) • f^{(p)}(k+1) - ((1/(p+1)) • B_{p+1}(0)) • f^{(p)}(k)
  have hB1 : ((1 / (p + 1 : ℝ)) • bernoulliFun (p + 1) 1) = (1 / (p + 1 : ℝ)) • bernoulliFun (p+1) 1 := rfl
  rw [hB1] at hIBP
  -- pull the scalars out of the pointwise smul boundary terms
  have hb1 : ((1 / (p + 1 : ℝ)) • bernoulliFun (p + 1) 1) • iteratedDerivWithin p f s ((k:ℝ)+1)
      = (1 / (p + 1 : ℝ)) • (bernoulliFun (p + 1) 1 • iteratedDerivWithin p f s ((k:ℝ)+1)) := by
    rw [smul_assoc]
  have hb0 : ((1 / (p + 1 : ℝ)) • bernoulliFun (p + 1) 0) • iteratedDerivWithin p f s (k:ℝ)
      = (1 / (p + 1 : ℝ)) • (bernoulliFun (p + 1) 0 • iteratedDerivWithin p f s (k:ℝ)) := by
    rw [smul_assoc]
  rw [hb1, hb0] at hIBP
  rw [eq_sub_iff_add_eq] at hIBP ⊢
  rw [add_comm]
  exact hIBP

end EulerMaclaurin
