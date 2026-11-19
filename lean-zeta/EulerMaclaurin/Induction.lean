module

public import EulerMaclaurin.FullFormula

/-!
# The Euler–Maclaurin formula by induction

Main result: for `f : ℝ → ℝ` of class `C^{p+2}` on an open set containing `[m, n]`,

$$\int_m^n f = \sum_{k=m}^{n-1} f(k) + \frac{f(n)-f(m)}{2}
  + \sum_{j=1}^{p} c_j \left(f^{(j)}(n) - f^{(j)}(m)\right)
  + c'_p \int_m^n \tilde B_{p+1}\, f^{(p+1)},$$

with `c_j = emCoeff j = (-1)^j B_{j+1}/(j+1)!` and `c'_p = emRemCoeff p = (-1)^{p+1}/(p+1)!`.

## Main results

* `eulerMaclaurin_identity` — the formula above.
-/

@[expose] public section

open scoped Interval BigOperators
open MeasureTheory intervalIntegral

noncomputable section

namespace EulerMaclaurin

/-- Packaged Euler–Maclaurin boundary sum `∑_{j=1}^{p} c_j · u j`. -/
noncomputable def emBoundary (p : ℕ) (u : ℕ → ℝ) : ℝ :=
  ∑ j ∈ Finset.Icc 1 p, emCoeff j * u j

@[simp]
theorem emBoundary_zero (u : ℕ → ℝ) : emBoundary 0 u = 0 := by
  simp [emBoundary]

theorem emBoundary_succ (p : ℕ) (u : ℕ → ℝ) :
    emBoundary (p + 1) u = emBoundary p u + emCoeff (p + 1) * u (p + 1) := by
  simp only [emBoundary]
  rw [Finset.sum_Icc_succ_top (by omega : 1 ≤ p + 1)]

/-- **Euler–Maclaurin summation, full form at finite order `p`.**

For `f : ℝ → ℝ` of class `C^{p+2}` on an open set `s` containing `[m,n]`:

`∫_m^n f = Σ_{k=m}^{n-1} f(k) + (f(n)-f(m))/2 + Σ_{j=1}^{p} emCoeff j · (f^{(j)}(n) - f^{(j)}(m))
            + emRemCoeff p · ∫_m^n B̃_{p+1} · f^{(p+1)}`

where `f^{(j)}` is `iteratedDerivWithin j f s`.

The two coefficient families are *absolute* — independent of `f`, `m`, `n` — which is what makes the
formula usable for quantitative estimates. -/
theorem eulerMaclaurin_identity {f : ℝ → ℝ} {s : Set ℝ} (hs : IsOpen s)
    {m n : ℕ} (hmn : m ≤ n)
    (hsub : Set.Icc (m : ℝ) (n : ℝ) ⊆ s)
    (p : ℕ) (hf : ContDiffOn ℝ ((p : ℕ) + 2) f s) :
    ∫ x in (m : ℝ)..(n : ℝ), f x
      = ∑ k ∈ Finset.Ico m n, f (k : ℝ) + (f (n : ℝ) - f (m : ℝ)) / 2
        + emBoundary p (fun j => iteratedDerivWithin j f s (n : ℝ)
            - iteratedDerivWithin j f s (m : ℝ))
        + emRemCoeff p * ∫ x in (m : ℝ)..(n : ℝ),
            (periodicBernoulli (p + 1) x : ℝ) • iteratedDerivWithin (p + 1) f s x := by
  -- Base case: `p = 0` is the `p = 0` range identity with `emRemCoeff 0 = -1`.
  induction p with
  | zero =>
    have h0 := integral_eq_sum_Ico_add_half_sub (E := ℝ) hs hmn hsub (by simpa using hf)
    simp only [emBoundary_zero, emRemCoeff_zero, zero_add]
    rw [h0]
    norm_num
    ring
  | succ p ih =>
    -- induction hypothesis at order `p`
    have hf' : ContDiffOn ℝ ((p : ℕ) + 2) f s := by
      have : ((p : ℕ) + 2) ≤ ((p + 1 : ℕ) + 2) := by
        have : ((p + 1 : ℕ) + 2) = ((p : ℕ) + 2) + 1 := by ring
        rw [this]; exact_mod_cast Nat.le_add_right _ 1
      exact hf.of_le (by
        show (((p : ℕ) + 2 : ℕ) : WithTop ℕ∞) ≤ ((((p + 1 : ℕ)) + 2 : ℕ) : WithTop ℕ∞)
        norm_cast)
    have hprev := ih hf'
    -- the recursion trading `∫ B̃_{p+1} f^{(p+1)}`
    have hrec := integral_periodicBernoulli_rec (E := ℝ) hs
      (p := p + 1) (by omega) hmn hsub hf
    -- `∫ B̃_{p+1} f^{(p+1)}` written as `∫ f^{(p+1)} • B̃_{p+1}`
    simp only [smul_eq_mul] at hprev hrec ⊢
    rw [hprev, hrec]
    have hb0 : bernoulliFun (p + 1 + 1) 0 = (bernoulli (p + 1 + 1) : ℝ) := bernoulliFun_eval_zero _
    rw [hb0]
    have hsucc : p + 1 + 1 = p + 2 := by ring
    have hsucc' : ((p + 1 : ℕ) : ℝ) + 1 = (p + 2 : ℝ) := by push_cast; ring
    rw [hsucc] at *
    rw [hsucc'] at *
    rw [emBoundary_succ, emRemCoeff_succ]
    have hcoef : emRemCoeff p * ((bernoulli (p + 2) : ℝ) / (p + 2 : ℝ)) = emCoeff (p + 1) :=
      emRemCoeff_mul_bernoulli p
    -- expand the product and identify the coefficients
    rw [mul_sub]
    conv_lhs => arg 2; arg 1; rw [← mul_assoc, hcoef]
    have hrem : emRemCoeff p * (1 / (p + 2 : ℝ)) = emRemCoeff p / (p + 2 : ℝ) := by ring
    conv_lhs => arg 2; arg 2; rw [← mul_assoc, hrem]
    ring

end EulerMaclaurin
