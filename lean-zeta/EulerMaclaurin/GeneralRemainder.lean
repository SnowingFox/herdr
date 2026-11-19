module

public import EulerMaclaurin.BernoulliBounds

/-!
# Euler–Maclaurin with an explicit remainder bound at general order

From the full identity

`∫_m^n f = Σ_{k=m}^{n-1} f(k) + (f(n)-f(m))/2
            + Σ_j c_j (f^{(j)}(n) - f^{(j)}(m)) + c'_p ∫_m^n B̃_{p+1} f^{(p+1)}`

and a uniform bound `|B̃_{p+1}| ≤ M`, we get

$$\left|\int_m^n f - \sum_{k=m}^{n-1} f(k) - \frac{f(n)-f(m)}{2}
    - \sum_{j=1}^{p} c_j \left(f^{(j)}(n)-f^{(j)}(m)\right)\right|
  \le \frac{M}{(p+1)!}\int_m^n \left|f^{(p+1)}\right| .$$

The constant `M/(p+1)!` is absolute in `f, m, n`; it depends only on the order `p`. For `p = 1` we
supply the sharp value `M = 1/2`, giving `1/2` in `abs_integral_sub_sum_sub_half_le`.

## Main results

* `abs_emRemCoeff` — `|emRemCoeff p| = 1/(p+1)!`.
* `abs_integral_sub_eulerMaclaurin_le` — the general-order bound.
-/

@[expose] public section

open scoped Interval BigOperators
open MeasureTheory intervalIntegral

noncomputable section

namespace EulerMaclaurin

/-- `|emRemCoeff p| = 1/(p+1)!`, because `emRemCoeff p = ±1/(p+1)!`. -/
theorem abs_emRemCoeff (p : ℕ) :
    |emRemCoeff p| = 1 / ((p + 1).factorial : ℝ) := by
  have hfac : (0 : ℝ) < ((p + 1).factorial : ℝ) := by
    exact_mod_cast Nat.factorial_pos (p + 1)
  simp only [emRemCoeff, abs_div, abs_pow, abs_neg, abs_one]
  rw [one_pow, abs_of_pos hfac]

/-- Decomposition of `∫_m^n B̃_p * g` into unit intervals, in real multiplication form. -/
theorem integral_periodicBernoulli_mul_eq_sum_Ico {g : ℝ → ℝ} {p : ℕ} {m n : ℕ}
    (hmn : m ≤ n)
    (hcont : ∀ k : ℕ, m ≤ k → k < n →
      ContinuousOn g (Set.Icc (k : ℝ) ((k : ℝ) + 1))) :
    ∫ x in (m : ℝ)..(n : ℝ), periodicBernoulli p x * g x
      = ∑ k ∈ Finset.Ico m n,
          ∫ x in (k : ℝ)..((k : ℝ) + 1), periodicBernoulli p x * g x :=
  integral_periodicBernoulli_mul_eq_sum_Ico' hmn hcont

/-- **Euler–Maclaurin remainder bound at general order.**

For `f : ℝ → ℝ` of class `C^{p+2}` on an open set containing `[m,n]`, and any `M ≥ 0` bounding
`|B_{p+1}|` on `[0,1]`, the difference between `∫_m^n f` and its Euler–Maclaurin approximation
through order `p` is bounded by `M/(p+1)! · ∫_m^n |f^{(p+1)}|`.

The constant `M/(p+1)!` does not depend on `f`, `m`, or `n`. -/
theorem abs_integral_sub_eulerMaclaurin_le {f : ℝ → ℝ} {s : Set ℝ} (hs : IsOpen s)
    {m n : ℕ} (hmn : m ≤ n)
    (hsub : Set.Icc (m : ℝ) (n : ℝ) ⊆ s)
    (p : ℕ) (hf : ContDiffOn ℝ ((p : ℕ) + 2) f s)
    {M : ℝ} (hMbound : ∀ y ∈ Set.Icc (0 : ℝ) 1, |bernoulliFun (p + 1) y| ≤ M) :
    |(∫ x in (m : ℝ)..(n : ℝ), f x)
        - (∑ k ∈ Finset.Ico m n, f (k : ℝ)) - (f (n : ℝ) - f (m : ℝ)) / 2
        - emBoundary p (fun j => iteratedDerivWithin j f s (n : ℝ)
            - iteratedDerivWithin j f s (m : ℝ))|
      ≤ M / ((p + 1).factorial : ℝ) * ∫ x in (m : ℝ)..(n : ℝ),
          |iteratedDerivWithin (p + 1) f s x| := by
  -- the Euler–Maclaurin identity, rearranged
  have hid := eulerMaclaurin_identity (f := f) (s := s) hs hmn hsub p hf
  simp only [smul_eq_mul] at hid ⊢
  have hval : (∫ x in (m : ℝ)..(n : ℝ), f x)
        - (∑ k ∈ Finset.Ico m n, f (k : ℝ)) - (f (n : ℝ) - f (m : ℝ)) / 2
        - emBoundary p (fun j => iteratedDerivWithin j f s (n : ℝ)
            - iteratedDerivWithin j f s (m : ℝ))
      = emRemCoeff p * ∫ x in (m : ℝ)..(n : ℝ),
          periodicBernoulli (p + 1) x * iteratedDerivWithin (p + 1) f s x := by
    rw [hid]
    ring
  rw [hval, abs_mul, abs_emRemCoeff]
  -- continuity of the top derivative on each unit subinterval
  have hsubk : ∀ k : ℕ, m ≤ k → k < n → Set.Icc (k : ℝ) ((k : ℝ) + 1) ⊆ s := by
    intro k hk1 hk2 x hx
    exact hsub ⟨(Nat.cast_le.mpr hk1).trans hx.1, by
      have h1 : (k : ℝ) + 1 ≤ (n : ℝ) := by
        have h : ((k : ℝ) + 1) = ((k + 1 : ℕ) : ℝ) := by push_cast; ring
        rw [h]; exact Nat.cast_le.mpr hk2
      exact hx.2.trans h1⟩
  have hple : (((p + 1 : ℕ)) : WithTop ℕ∞) ≤ ((((p + 1) + 1 : ℕ)) : WithTop ℕ∞) := by
    show (((p + 1 : ℕ) : ℕ∞) : WithTop ℕ∞) ≤ ((((p + 1) + 1 : ℕ) : ℕ∞) : WithTop ℕ∞)
    norm_cast
    omega
  have hcont : ∀ k : ℕ, m ≤ k → k < n →
      ContinuousOn (iteratedDerivWithin (p + 1) f s) (Set.Icc (k : ℝ) ((k : ℝ) + 1)) :=
    fun k hk1 hk2 => (hf.continuousOn_iteratedDerivWithin (n := (((p + 1) + 1 : ℕ) : WithTop ℕ∞))
      (m := p + 1) hple hs.uniqueDiffOn).mono (hsubk k hk1 hk2)
  -- decompose and bound
  have hdec : ∫ x in (m : ℝ)..(n : ℝ),
        periodicBernoulli (p + 1) x * iteratedDerivWithin (p + 1) f s x
      = ∑ k ∈ Finset.Ico m n,
          ∫ x in (k : ℝ)..((k : ℝ) + 1),
            periodicBernoulli (p + 1) x * iteratedDerivWithin (p + 1) f s x :=
    integral_periodicBernoulli_mul_eq_sum_Ico hmn (fun k hk1 hk2 => hcont k hk1 hk2)
  rw [hdec]
  have hnorm : |∑ k ∈ Finset.Ico m n,
        ∫ x in (k : ℝ)..((k : ℝ) + 1),
          periodicBernoulli (p + 1) x * iteratedDerivWithin (p + 1) f s x|
      ≤ M * ∫ x in (m : ℝ)..(n : ℝ), |iteratedDerivWithin (p + 1) f s x| := by
    calc |∑ k ∈ Finset.Ico m n,
          ∫ x in (k : ℝ)..((k : ℝ) + 1),
            periodicBernoulli (p + 1) x * iteratedDerivWithin (p + 1) f s x|
        ≤ ∑ k ∈ Finset.Ico m n,
            |∫ x in (k : ℝ)..((k : ℝ) + 1),
              periodicBernoulli (p + 1) x * iteratedDerivWithin (p + 1) f s x| :=
          Finset.abs_sum_le_sum_abs _ _
      _ ≤ ∑ k ∈ Finset.Ico m n,
            M * ∫ x in (k : ℝ)..((k : ℝ) + 1),
              |iteratedDerivWithin (p + 1) f s x| := by
          apply Finset.sum_le_sum
          intro k hk
          exact abs_integral_unit_periodicBernoulli_mul_le hMbound
            (hcont k (Finset.mem_Ico.mp hk).1 (Finset.mem_Ico.mp hk).2)
      _ = M * ∑ k ∈ Finset.Ico m n,
            ∫ x in (k : ℝ)..((k : ℝ) + 1), |iteratedDerivWithin (p + 1) f s x| := by
          rw [Finset.mul_sum]
      _ = M * ∫ x in (m : ℝ)..(n : ℝ), |iteratedDerivWithin (p + 1) f s x| := by
          congr 1
          have hInt : ∀ k : ℕ, m ≤ k → k < n →
              IntervalIntegrable (fun x => |iteratedDerivWithin (p + 1) f s x|) volume
                (k : ℝ) ((k : ℝ) + 1) := by
            intro k hk1 hk2
            apply ContinuousOn.intervalIntegrable
            rw [Set.uIcc_of_le (by linarith : (k : ℝ) ≤ (k : ℝ) + 1)]
            exact (hcont k hk1 hk2).abs
          have hkey := sum_integral_adjacent_intervals_Ico (μ := volume)
            (f := fun x => |iteratedDerivWithin (p + 1) f s x|)
            (a := fun k : ℕ => (k : ℝ)) hmn
            (fun k hk => by
              have := hInt k hk.1 hk.2
              simpa [Nat.cast_add, Nat.cast_one] using this)
          rw [← hkey]
          apply Finset.sum_congr rfl
          intro k _
          norm_num
  calc 1 / ((p + 1).factorial : ℝ) * |∑ k ∈ Finset.Ico m n,
        ∫ x in (k : ℝ)..((k : ℝ) + 1),
          periodicBernoulli (p + 1) x * iteratedDerivWithin (p + 1) f s x|
      ≤ 1 / ((p + 1).factorial : ℝ) *
          (M * ∫ x in (m : ℝ)..(n : ℝ), |iteratedDerivWithin (p + 1) f s x|) := by
        apply mul_le_mul_of_nonneg_left hnorm
        positivity
    _ = M / ((p + 1).factorial : ℝ) * ∫ x in (m : ℝ)..(n : ℝ),
          |iteratedDerivWithin (p + 1) f s x| := by ring

end EulerMaclaurin
