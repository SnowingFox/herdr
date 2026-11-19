module

public import EulerMaclaurin.BaseRange

/-!
# Bounds on the periodic Bernoulli functions and their integrals

To turn the Euler–Maclaurin identity into an *inequality*, we need uniform bounds on the periodic
Bernoulli functions. Everything here is done on a single unit interval `[k, k+1]`, where `B̃_p`
agrees a.e. with the continuous polynomial `B_p(· - k)`; this keeps every integrability obligation
a statement about continuous functions.

The sharp constant for `p = 1` is `1/2`, since `B̃_1(x) = {x} - 1/2`.

## Main results

* `abs_periodicBernoulli_one_le` — `|B̃_1| ≤ 1/2`, sharp.
* `norm_integral_unit_periodicBernoulli_smul_le` — `‖∫_k^{k+1} B̃_p • g‖ ≤ M ∫_k^{k+1} ‖g‖`,
  given `|B_p| ≤ M` on `[0,1]`.
-/

@[expose] public section

open scoped Interval BigOperators
open MeasureTheory intervalIntegral

noncomputable section

namespace EulerMaclaurin

/-- `B̃_1(x) = {x} - 1/2`. -/
theorem periodicBernoulli_one_eq (x : ℝ) : periodicBernoulli 1 x = Int.fract x - 1 / 2 := by
  simp [periodicBernoulli, bernoulliFun_one]

/-- **`|B̃_1| ≤ 1/2`**, sharp: equality holds at the integers, where `B̃_1 = -1/2`.
(At the half-integers `B̃_1 = 0`, so they are not extremal.) -/
theorem abs_periodicBernoulli_one_le (x : ℝ) : |periodicBernoulli 1 x| ≤ 1 / 2 := by
  rw [periodicBernoulli_one_eq, abs_le]
  constructor
  · linarith [Int.fract_nonneg x]
  · linarith [Int.fract_lt_one x]

/-- **Integral bound on a unit interval.**

If `|B_p| ≤ M` on `[0,1]` and `g` is continuous on `[k, k+1]`, then
`‖∫_k^{k+1} B̃_p • g‖ ≤ M ∫_k^{k+1} ‖g‖`. -/
theorem norm_integral_unit_periodicBernoulli_smul_le {E : Type*} [NormedAddCommGroup E]
    [NormedSpace ℝ E] [CompleteSpace E] {g : ℝ → E} {p : ℕ} {M : ℝ} {k : ℕ}
    (hM : ∀ y ∈ Set.Icc (0 : ℝ) 1, |bernoulliFun p y| ≤ M)
    (hg : ContinuousOn g (Set.Icc (k : ℝ) ((k : ℝ) + 1))) :
    ‖∫ x in (k : ℝ)..((k : ℝ) + 1), periodicBernoulli p x • g x‖
      ≤ M * ∫ x in (k : ℝ)..((k : ℝ) + 1), ‖g x‖ := by
  have hkle : (k : ℝ) ≤ (k : ℝ) + 1 := by linarith
  -- replace `B̃_p` by the continuous polynomial on the unit interval
  have hcongr : ∫ x in (k : ℝ)..((k : ℝ) + 1), periodicBernoulli p x • g x
      = ∫ x in (k : ℝ)..((k : ℝ) + 1), bernoulliFun p (x - k) • g x :=
    integral_periodicBernoulli_smul p k g
  rw [hcongr]
  have hcont : ContinuousOn (fun x => bernoulliFun p (x - k) • g x)
      (Set.uIcc (k : ℝ) ((k : ℝ) + 1)) := by
    rw [Set.uIcc_of_le hkle]
    exact (((continuous_bernoulliFun p).comp
      (continuous_id.sub continuous_const)).continuousOn).smul hg
  have hnorm_cont : ContinuousOn (fun x => ‖g x‖) (Set.uIcc (k : ℝ) ((k : ℝ) + 1)) := by
    rw [Set.uIcc_of_le hkle]
    exact hg.norm
  -- pointwise bound
  have hpt : ∀ x ∈ Set.Icc (k : ℝ) ((k : ℝ) + 1),
      ‖bernoulliFun p (x - k) • g x‖ ≤ M * ‖g x‖ := by
    intro x hx
    have hx' : x - k ∈ Set.Icc (0 : ℝ) 1 := ⟨by linarith [hx.1], by linarith [hx.2]⟩
    rw [norm_smul, Real.norm_eq_abs]
    exact mul_le_mul_of_nonneg_right (hM _ hx') (norm_nonneg _)
  calc ‖∫ x in (k : ℝ)..((k : ℝ) + 1), bernoulliFun p (x - k) • g x‖
      ≤ ∫ x in (k : ℝ)..((k : ℝ) + 1), ‖bernoulliFun p (x - k) • g x‖ :=
        intervalIntegral.norm_integral_le_integral_norm hkle
    _ ≤ ∫ x in (k : ℝ)..((k : ℝ) + 1), M * ‖g x‖ := by
        refine intervalIntegral.integral_mono_on hkle ?_ ?_ hpt
        · exact hcont.norm.intervalIntegrable
        · exact (ContinuousOn.mul continuousOn_const hnorm_cont).intervalIntegrable
    _ = M * ∫ x in (k : ℝ)..((k : ℝ) + 1), ‖g x‖ :=
        intervalIntegral.integral_const_mul M _

/-- **Real-valued integral bound on a unit interval.** If `|B_p| ≤ M` on `[0,1]` and `g` is
continuous on `[k, k+1]`, then `|∫_k^{k+1} B̃_p · g| ≤ M ∫_k^{k+1} |g|`. -/
theorem abs_integral_unit_periodicBernoulli_mul_le {g : ℝ → ℝ} {p : ℕ} {M : ℝ} {k : ℕ}
    (hM : ∀ y ∈ Set.Icc (0 : ℝ) 1, |bernoulliFun p y| ≤ M)
    (hg : ContinuousOn g (Set.Icc (k : ℝ) ((k : ℝ) + 1))) :
    |∫ x in (k : ℝ)..((k : ℝ) + 1), periodicBernoulli p x * g x|
      ≤ M * ∫ x in (k : ℝ)..((k : ℝ) + 1), |g x| := by
  have := norm_integral_unit_periodicBernoulli_smul_le (E := ℝ) hM hg
  simpa only [smul_eq_mul, Real.norm_eq_abs] using this

end EulerMaclaurin
