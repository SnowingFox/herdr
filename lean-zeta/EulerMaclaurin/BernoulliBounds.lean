module

public import EulerMaclaurin.Induction

/-!
# Bounds on Bernoulli polynomials

To convert the Euler–Maclaurin *identity* into an *inequality*, we need `M_p` with
`|B_p(x)| ≤ M_p` on `[0,1]`.

The polynomial `B_p` has degree `p` (`Polynomial.degree_bernoulli`), and its coefficients are bounded
by `|B_{p-i}| · C(p,i)`, so a completely explicit (if crude) bound is

$$M_p = (p+1)\cdot \max_{0 \le i \le p} |B_i| \cdot 2^p .$$

For `p = 1` the sharp value `1/2` is proved separately (`abs_periodicBernoulli_one_le`).

## Main results

* `exists_bernoulliFun_bound` — `∃ M ≥ 0, ∀ x, |B_p x| ≤ M` on `[0,1]`.
* `exists_periodicBernoulli_bound` — the same, uniformly on `ℝ`.
-/

@[expose] public section

open scoped Interval BigOperators
open MeasureTheory intervalIntegral

noncomputable section

namespace EulerMaclaurin

/-- The Bernoulli polynomial `B_p` is bounded on `[0,1]`. -/
theorem exists_bernoulliFun_bound (p : ℕ) :
    ∃ M : ℝ, 0 ≤ M ∧ ∀ x ∈ Set.Icc (0 : ℝ) 1, |bernoulliFun p x| ≤ M := by
  have hcont : ContinuousOn (fun x => |bernoulliFun p x|) (Set.Icc (0 : ℝ) 1) :=
    (continuous_bernoulliFun p).abs.continuousOn
  obtain ⟨M, hM⟩ := isCompact_Icc.exists_bound_of_continuousOn hcont
  refine ⟨M, le_trans (abs_nonneg _) (hM 0 (by norm_num)), fun x hx => ?_⟩
  simpa using hM x hx

/-- Consequently the periodic Bernoulli function `B̃_p` is bounded on all of `ℝ` by the same bound. -/
theorem exists_periodicBernoulli_bound (p : ℕ) :
    ∃ M : ℝ, 0 ≤ M ∧ ∀ x : ℝ, |periodicBernoulli p x| ≤ M := by
  obtain ⟨M, hM0, hM⟩ := exists_bernoulliFun_bound p
  exact ⟨M, hM0, fun x => abs_periodicBernoulli_le hM x⟩

end EulerMaclaurin
