module

public import EulerMaclaurin.Bounds

/-!
# Euler–Maclaurin with an explicit remainder bound

Combining the `p = 0` range identity

`∫_m^n f = ∑_{k=m}^{n-1} f(k) + (f(n)-f(m))/2 - ∫_m^n B̃_1 f'`

with the sharp bound `|B̃_1| ≤ 1/2` gives the classical trapezoid estimate

$$\left|\int_m^n f - \sum_{k=m}^{n-1} f(k) - \frac{f(n)-f(m)}{2}\right|
  \le \frac{1}{2}\int_m^n |f'| .$$

The constant `1/2` is *sharp*: `B̃_1` attains `-1/2` at the integers (and `0` at the
half-integers, so the extremum is at the integers, not between them).

## Main results

* `iteratedDerivWithin_one_eq_of_hasDerivAt` — bridge from `HasDerivAt` to `iteratedDerivWithin`.
* `abs_integral_sub_sum_sub_half_le` — the `p = 1` explicit bound.
-/

@[expose] public section

open scoped Interval BigOperators
open MeasureTheory intervalIntegral

noncomputable section

namespace EulerMaclaurin

/-- On an open set, `iteratedDerivWithin 1 f s` agrees with any `f'` that is a derivative of `f`. -/
theorem iteratedDerivWithin_one_eq_of_hasDerivAt {f f' : ℝ → ℝ} {s : Set ℝ} (hs : IsOpen s)
    (hderiv : ∀ x ∈ s, HasDerivAt f (f' x) x) {x : ℝ} (hx : x ∈ s) :
    iteratedDerivWithin 1 f s x = f' x := by
  rw [iteratedDerivWithin_one, derivWithin_of_mem_nhds (hs.mem_nhds hx)]
  exact (hderiv x hx).deriv

/-- A uniform bound on `|B_p|` on `[0,1]` gives a uniform bound on `|B̃_p|` everywhere. -/
theorem abs_periodicBernoulli_le_of_Icc {p : ℕ} {M : ℝ}
    (hM : ∀ y ∈ Set.Icc (0 : ℝ) 1, |bernoulliFun p y| ≤ M) (x : ℝ) :
    |periodicBernoulli p x| ≤ M :=
  abs_periodicBernoulli_le hM x

/-- `|B̃_1| ≤ 1/2`, in the form consumed by the integral bound. -/
theorem abs_bernoulliFun_one_le {y : ℝ} (hy : y ∈ Set.Icc (0 : ℝ) 1) :
    |bernoulliFun 1 y| ≤ 1 / 2 := by
  rw [bernoulliFun_one, abs_le]
  constructor <;> linarith [hy.1, hy.2]

/-- **Euler–Maclaurin, `p = 1`, with the explicit constant `1/2`.**

For `f : ℝ → ℝ` of class `C²` on an open set `s` containing `[m, n]`, with `f'` a derivative of `f`
on `s`,

`|∫_m^n f − ∑_{k=m}^{n−1} f(k) − (f(n) − f(m))/2| ≤ (1/2) ∫_m^n |f'|`.

Only `f'` appears on the right, and the constant `1/2` is best possible. -/
theorem abs_integral_sub_sum_sub_half_le {f f' : ℝ → ℝ} {s : Set ℝ} (hs : IsOpen s)
    {m n : ℕ} (hmn : m ≤ n)
    (hsub : Set.Icc (m : ℝ) (n : ℝ) ⊆ s)
    (hf : ContDiffOn ℝ 2 f s)
    (hderiv : ∀ x ∈ s, HasDerivAt f (f' x) x) :
    |(∫ x in (m : ℝ)..(n : ℝ), f x)
        - (∑ k ∈ Finset.Ico m n, f (k : ℝ)) - (f (n : ℝ) - f (m : ℝ)) / 2|
      ≤ (1 / 2) * ∫ x in (m : ℝ)..(n : ℝ), |f' x| := by
  have hmn' : (m : ℝ) ≤ (n : ℝ) := Nat.cast_le.mpr hmn
  -- the range identity, rearranged
  have hval : (∫ x in (m : ℝ)..(n : ℝ), f x)
        - (∑ k ∈ Finset.Ico m n, f (k : ℝ)) - (f (n : ℝ) - f (m : ℝ)) / 2
      = -∫ x in (m : ℝ)..(n : ℝ),
          periodicBernoulli 1 x • iteratedDerivWithin 1 f s x := by
    have h := integral_eq_sum_Ico_add_half_sub hs hmn hsub hf
    rw [smul_eq_mul] at h
    have e1 : (1 / 2 : ℝ) * (f (n : ℝ) - f (m : ℝ)) = (f (n : ℝ) - f (m : ℝ)) / 2 := by ring
    rw [e1] at h
    rw [h]
    ring
  rw [hval, abs_neg]
  -- `C²` gives continuity of the first derivative on every unit subinterval
  have hsubk : ∀ k : ℕ, m ≤ k → k < n → Set.Icc (k : ℝ) ((k : ℝ) + 1) ⊆ s := by
    intro k hk1 hk2 x hx
    exact hsub ⟨(Nat.cast_le.mpr hk1).trans hx.1, by
      have h1 : (k : ℝ) + 1 ≤ (n : ℝ) := by
        have h : ((k : ℝ) + 1) = ((k + 1 : ℕ) : ℝ) := by push_cast; ring
        rw [h]; exact Nat.cast_le.mpr hk2
      exact hx.2.trans h1⟩
  have hone : (((1 : ℕ)) : WithTop ℕ∞) ≤ ((2 : ℕ) : WithTop ℕ∞) := by
    show (((1 : ℕ) : ℕ∞) : WithTop ℕ∞) ≤ (((2 : ℕ) : ℕ∞) : WithTop ℕ∞); norm_cast
  have hcont1 : ∀ k : ℕ, m ≤ k → k < n →
      ContinuousOn (iteratedDerivWithin 1 f s) (Set.Icc (k : ℝ) ((k : ℝ) + 1)) :=
    fun k hk1 hk2 => (hf.continuousOn_iteratedDerivWithin (n := ((2:ℕ) : WithTop ℕ∞))
      (m := 1) hone hs.uniqueDiffOn).mono (hsubk k hk1 hk2)
  -- decompose the range integral into unit intervals
  rw [integral_periodicBernoulli_smul_eq_sum_Ico hmn hcont1]
  have hnorm_goal : ‖∑ k ∈ Finset.Ico m n,
        ∫ x in (k : ℝ)..((k : ℝ) + 1),
          periodicBernoulli 1 x • iteratedDerivWithin 1 f s x‖
      ≤ (1 / 2) * ∫ x in (m : ℝ)..(n : ℝ), ‖f' x‖ := by
    calc ‖∑ k ∈ Finset.Ico m n,
          ∫ x in (k : ℝ)..((k : ℝ) + 1),
            periodicBernoulli 1 x • iteratedDerivWithin 1 f s x‖
        ≤ ∑ k ∈ Finset.Ico m n,
            ‖∫ x in (k : ℝ)..((k : ℝ) + 1),
              periodicBernoulli 1 x • iteratedDerivWithin 1 f s x‖ := norm_sum_le _ _
      _ ≤ ∑ k ∈ Finset.Ico m n,
            (1 / 2) * ∫ x in (k : ℝ)..((k : ℝ) + 1),
              ‖iteratedDerivWithin 1 f s x‖ := by
          apply Finset.sum_le_sum
          intro k hk
          exact norm_integral_unit_periodicBernoulli_smul_le
            (fun y hy => abs_bernoulliFun_one_le hy)
            (hcont1 k (Finset.mem_Ico.mp hk).1 (Finset.mem_Ico.mp hk).2)
      _ = (1 / 2) * ∑ k ∈ Finset.Ico m n,
            ∫ x in (k : ℝ)..((k : ℝ) + 1), ‖iteratedDerivWithin 1 f s x‖ := by
          rw [Finset.mul_sum]
      _ = (1 / 2) * ∫ x in (m : ℝ)..(n : ℝ), ‖iteratedDerivWithin 1 f s x‖ := by
          congr 1
          have hInt : ∀ k : ℕ, m ≤ k → k < n →
              IntervalIntegrable (fun x => ‖iteratedDerivWithin 1 f s x‖) volume
                (k : ℝ) ((k : ℝ) + 1) := by
            intro k hk1 hk2
            apply ContinuousOn.intervalIntegrable
            rw [Set.uIcc_of_le (by linarith : (k : ℝ) ≤ (k : ℝ) + 1)]
            exact (hcont1 k hk1 hk2).norm
          have hkey := sum_integral_adjacent_intervals_Ico (μ := volume)
            (f := fun x => ‖iteratedDerivWithin 1 f s x‖)
            (a := fun k : ℕ => (k : ℝ)) hmn
            (fun k hk => by
              have := hInt k hk.1 hk.2
              simpa [Nat.cast_add, Nat.cast_one] using this)
          rw [← hkey]
          apply Finset.sum_congr rfl
          intro k _
          norm_num
      _ = (1 / 2) * ∫ x in (m : ℝ)..(n : ℝ), ‖f' x‖ := by
          congr 1
          apply intervalIntegral.integral_congr
          intro x hx
          rw [Set.uIcc_of_le hmn'] at hx
          simp only
          rw [iteratedDerivWithin_one_eq_of_hasDerivAt hs hderiv (hsub hx)]
  -- transport from `‖·‖` to `|·|`
  simpa [Real.norm_eq_abs] using hnorm_goal

end EulerMaclaurin
