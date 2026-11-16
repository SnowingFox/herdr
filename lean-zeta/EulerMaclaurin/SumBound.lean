module

public import EulerMaclaurin.ZetaMain
public import EulerMaclaurin.ZetaSummand

/-!
# Bounds on Dirichlet-type sums, in consumer form

`abs_eulerMaclaurin_rpow_le_uniform` bounds the *real* sum `Σ k^{-σ}`. A consumer working with the
complex summand `k^{-s}` — the Dirichlet-series case — needs a norm bound, not an absolute-value
bound. This file supplies it in the shape that composes.

The route is deliberately elementary and avoids any `ContDiff` statement for the complex function
`x ↦ (x:ℂ)^{-s}`: term-by-term, `‖k^{-s}‖ = k^{-Re s}`, so the complex sum is dominated by the real
sum at `σ = Re s`, and the real bound does the work.

## Main results

* `norm_cpow_neg_natCast` — `‖(k:ℂ)^{-s}‖ = k^{-Re s}` for `k ≥ 1`.
* `norm_sum_Ico_cpow_le` — the sum bound: for `Re s > 0` and `1 ≤ m`,
  `‖Σ_{k∈Ico m N} k^{-s}‖ ≤ m^{-σ} + (m^{1-σ} - N^{1-σ})/(σ-1)` when `σ ≠ 1`, and the log form at
  `σ = 1`. Both are **uniform in `N`**.
* `norm_sum_Ico_cpow_le_uniform` — the cruder but `N`-free form `‖Σ‖ ≤ 2 m^{-σ} + m^{1-σ}/(σ-1)`
  (resp. a log form), which is what a strip argument quotes.

## Why these shapes

A sum bound is used by summing over a range and letting the upper end go to infinity, so the useful
statement has the *upper* limit appearing only in a term that is bounded below or vanishes. The
`N`-dependent terms here are `-N^{1-σ}/(σ-1) ≤ 0` (vanishing for `σ > 1`, bounded for `σ < 1`) and
the negative `-N^{-σ}/2`, so we can always drop them — that is the `_uniform` corollary.
-/

@[expose] public section

open scoped Interval BigOperators
open MeasureTheory intervalIntegral Complex

noncomputable section

namespace EulerMaclaurin

/-- `‖(k : ℂ)^{-s}‖ = k^{-Re s}` for `k ≥ 1`. -/
theorem norm_cpow_neg_natCast {s : ℂ} {k : ℕ} (hk : 1 ≤ k) :
    ‖((k : ℝ) : ℂ) ^ (-s)‖ = (k : ℝ) ^ (-s.re) := by
  have hk0 : (0 : ℝ) < (k : ℝ) := by exact_mod_cast hk
  rw [Complex.norm_cpow_eq_rpow_re_of_pos hk0]
  simp

/-- `‖(k : ℂ)^{-s}‖ = k^{-Re s}` for `k ≥ 1`, with the cast to `ℂ` written as `↑k`. -/
theorem norm_cpow_neg_nat {s : ℂ} {k : ℕ} (hk : 1 ≤ k) :
    ‖((k : ℂ)) ^ (-s)‖ = (k : ℝ) ^ (-s.re) := by
  have hk0 : (0 : ℝ) < (k : ℝ) := by exact_mod_cast hk
  rw [show ((k : ℂ)) = (((k : ℝ)) : ℂ) by push_cast; ring]
  exact norm_cpow_neg_natCast hk

/-- `∫_m^n x^{-σ} = (n^{1-σ} - m^{1-σ})/(1-σ)` for `0 < m ≤ n` and `σ ≠ 1`.

Proved directly from the antiderivative `x ↦ x^{1-σ}/(1-σ)`; this covers `σ < 1`, where the
`x^{-s-1}` form in `integral_rpow_neg_sub_one` does not apply. -/
theorem integral_rpow_neg_eq {σ : ℝ} (hσ1 : σ ≠ 1) {m n : ℝ} (hm : 0 < m) (hmn : m ≤ n) :
    ∫ x in m..n, x ^ (-σ) = (n ^ (1 - σ) - m ^ (1 - σ)) / (1 - σ) := by
  have h1s : (1 : ℝ) - σ ≠ 0 := sub_ne_zero.mpr (Ne.symm hσ1)
  have hderiv : ∀ x ∈ Set.uIcc m n,
      HasDerivAt (fun y : ℝ => y ^ (1 - σ) / (1 - σ)) (x ^ (-σ)) x := by
    intro x hx
    rw [Set.uIcc_of_le hmn] at hx
    have hx0 : x ≠ 0 := ne_of_gt (lt_of_lt_of_le hm hx.1)
    have hb := Real.hasDerivAt_rpow_const (x := x) (p := 1 - σ) (Or.inl hx0)
    have h2 := hb.div_const (1 - σ)
    convert h2 using 1
    field_simp
    ring
  rw [intervalIntegral.integral_eq_sub_of_hasDerivAt hderiv]
  · rw [div_eq_mul_inv, div_eq_mul_inv]; ring
  · apply ContinuousOn.intervalIntegrable
    rw [Set.uIcc_of_le hmn]
    intro x hx
    have hx0 : x ≠ 0 := ne_of_gt (lt_of_lt_of_le hm hx.1)
    exact ((Real.hasDerivAt_rpow_const (x := x) (p := -σ) (Or.inl hx0)).continuousAt).continuousWithinAt

/-- The Euler–Maclaurin upper bound for the real sum, solved for the sum, in the regime
`0 < σ < 1`.

From `|Σ - ∫ - D| ≤ D` we get `Σ ≤ ∫ + 2D`, and `∫_m^n x^{-σ} = (m^{1-σ} - n^{1-σ})/(1-σ)`.
Both `N`-dependent terms are non-positive (since `1 - σ > 0` and `N^{-σ} > 0`), so the right-hand
side is at most `m^{1-σ}/(1-σ) + m^{-σ}`. -/
theorem sum_Ico_rpow_le_of_lt_one_raw {σ : ℝ} (hσ : 0 < σ) (hσ1 : σ < 1)
    {m n : ℕ} (hm : 1 ≤ m) (hmn : m ≤ n) :
    ∑ k ∈ Finset.Ico m n, (k : ℝ) ^ (-σ)
      ≤ ((n : ℝ) ^ (1 - σ) - (m : ℝ) ^ (1 - σ)) / (1 - σ)
        + ((m : ℝ) ^ (-σ) - (n : ℝ) ^ (-σ)) := by
  have hm0 : (0 : ℝ) < (m : ℝ) := by exact_mod_cast hm
  have hn0 : (0 : ℝ) < (n : ℝ) := by exact_mod_cast (le_trans hm hmn)
  have hmn' : (m : ℝ) ≤ (n : ℝ) := Nat.cast_le.mpr hmn
  have h := abs_eulerMaclaurin_rpow_le hσ hm hmn
  have h1 : (∑ k ∈ Finset.Ico m n, (k : ℝ) ^ (-σ))
      - (∫ x in (m : ℝ)..(n : ℝ), x ^ (-σ))
      - ((m : ℝ) ^ (-σ) - (n : ℝ) ^ (-σ)) / 2
      ≤ ((m : ℝ) ^ (-σ) - (n : ℝ) ^ (-σ)) / 2 := (abs_le.mp h).2
  -- `∫ x^{-σ} = x^{1-σ}/(1-σ)`, the `σ < 1` case of `∫ x^{-s-1}`
  have hInt : ∫ x in (m : ℝ)..(n : ℝ), x ^ (-σ)
      = ((n : ℝ) ^ (1 - σ) - (m : ℝ) ^ (1 - σ)) / (1 - σ) :=
    integral_rpow_neg_eq (by linarith : σ ≠ 1) hm0 hmn'
  rw [hInt] at h1
  linarith

/-- **Uniform-in-`N` bound, converged regime `σ > 1`.**

`Σ_{k=m}^{N-1} k^{-σ} ≤ m^{1-σ}/(σ-1) + m^{-σ}`, with no `N` on the right.

Here `1 - σ < 0`, so `n^{1-σ} ≤ m^{1-σ}` and the `n`-terms are bounded above by their `m`-values.
This is the only regime in which the partial sums are uniformly bounded: for `σ ≤ 1` they grow like
`N^{1-σ}` (see `sum_Ico_rpow_le_of_lt_one`). -/
theorem sum_Ico_rpow_le_const_of_one_lt {σ : ℝ} (hσ : 1 < σ)
    {m n : ℕ} (hm : 1 ≤ m) (hmn : m ≤ n) :
    ∑ k ∈ Finset.Ico m n, (k : ℝ) ^ (-σ)
      ≤ (m : ℝ) ^ (1 - σ) / (σ - 1) + (m : ℝ) ^ (-σ) := by
  have hσ0 : 0 < σ := by linarith
  have hm0 : (0 : ℝ) < (m : ℝ) := by exact_mod_cast hm
  have hn0 : (0 : ℝ) < (n : ℝ) := by exact_mod_cast (le_trans hm hmn)
  have hmn' : (m : ℝ) ≤ (n : ℝ) := Nat.cast_le.mpr hmn
  have hpos : (0 : ℝ) < σ - 1 := by linarith
  have h := abs_eulerMaclaurin_rpow_le hσ0 hm hmn
  -- write the integral in the `σ - 1` form directly
  have hInt : ∫ x in (m : ℝ)..(n : ℝ), x ^ (-σ)
      = ((m : ℝ) ^ (1 - σ) - (n : ℝ) ^ (1 - σ)) / (σ - 1) := by
    rw [integral_rpow_neg_eq (by linarith : σ ≠ 1) hm0 hmn']
    have hne1 : (1 : ℝ) - σ ≠ 0 := by linarith
    have hne2 : σ - 1 ≠ 0 := by linarith
    field_simp
    ring
  rw [hInt] at h
  -- extract the upper bound `S ≤ I + 2D`
  have h1 := (abs_le.mp h).2
  -- `(m^{1-σ} - n^{1-σ})/(σ-1) ≤ m^{1-σ}/(σ-1)`  since `n^{1-σ} ≥ 0`
  have hn1 : (0 : ℝ) ≤ (n : ℝ) ^ (1 - σ) :=
    le_of_lt (Real.rpow_pos_of_pos hn0 _)
  have hn2 : (0 : ℝ) ≤ (n : ℝ) ^ (-σ) :=
    le_of_lt (Real.rpow_pos_of_pos hn0 _)
  have hkey : ((m : ℝ) ^ (1 - σ) - (n : ℝ) ^ (1 - σ)) / (σ - 1)
      ≤ (m : ℝ) ^ (1 - σ) / (σ - 1) := by
    rw [sub_div]
    have : 0 ≤ (n : ℝ) ^ (1 - σ) / (σ - 1) := div_nonneg hn1 hpos.le
    linarith
  linarith

/-- **Explicit-in-`N` bound, non-convergent regime `0 < σ < 1`.**

`Σ_{k=m}^{N-1} k^{-σ} ≤ N^{1-σ}/(1-σ) + m^{-σ}`.

There is deliberately no `N`-free version in this regime: the partial sums grow like `N^{1-σ}`, so
any such statement would be false. This is the form a strip argument uses, keeping `N` (typically
`N ≈ |Im s|`) explicit. -/
theorem sum_Ico_rpow_le_of_lt_one {σ : ℝ} (hσ : 0 < σ) (hσ1 : σ < 1)
    {m n : ℕ} (hm : 1 ≤ m) (hmn : m ≤ n) :
    ∑ k ∈ Finset.Ico m n, (k : ℝ) ^ (-σ)
      ≤ (n : ℝ) ^ (1 - σ) / (1 - σ) + (m : ℝ) ^ (-σ) := by
  have hm0 : (0 : ℝ) < (m : ℝ) := by exact_mod_cast hm
  have hn0 : (0 : ℝ) < (n : ℝ) := by exact_mod_cast (le_trans hm hmn)
  have hmn' : (m : ℝ) ≤ (n : ℝ) := Nat.cast_le.mpr hmn
  have hpos : (0 : ℝ) < 1 - σ := by linarith
  have hbase := sum_Ico_rpow_le_of_lt_one_raw hσ hσ1 hm hmn
  -- drop `- m^{1-σ}/(1-σ) ≤ 0` and `- n^{-σ} ≤ 0`
  have hm1 : 0 ≤ (m : ℝ) ^ (1 - σ) := le_of_lt (Real.rpow_pos_of_pos hm0 _)
  have hn2 : 0 ≤ (n : ℝ) ^ (-σ) := le_of_lt (Real.rpow_pos_of_pos hn0 _)
  have hkey : ((n : ℝ) ^ (1 - σ) - (m : ℝ) ^ (1 - σ)) / (1 - σ)
      ≤ (n : ℝ) ^ (1 - σ) / (1 - σ) := by
    rw [sub_div]
    have : 0 ≤ (m : ℝ) ^ (1 - σ) / (1 - σ) := div_nonneg hm1 hpos.le
    linarith
  linarith

/-! ### Complex-valued consumer bounds

The theorems above are for the real summand `k^{-σ}`. A Dirichlet-series consumer works with
`k^{-s}`, so we transfer term-by-term via `‖k^{-s}‖ = k^{-Re s}` and apply the real bound to the
majorant. The result is a norm bound on the complex partial sum with the same constants. -/

/-- Termwise domination transfers a bound on the real sum to the complex sum. -/
theorem norm_sum_Ico_cpow_le_of_sum_le {s : ℂ} {m n : ℕ}
    {B : ℝ} (hB : ∀ k ∈ Finset.Ico m n, ‖((k : ℂ)) ^ (-s)‖ ≤ (k : ℝ) ^ (-s.re))
    (hsum : ∑ k ∈ Finset.Ico m n, (k : ℝ) ^ (-s.re) ≤ B) :
    ‖∑ k ∈ Finset.Ico m n, ((k : ℂ)) ^ (-s)‖ ≤ B := by
  calc ‖∑ k ∈ Finset.Ico m n, ((k : ℂ)) ^ (-s)‖
      ≤ ∑ k ∈ Finset.Ico m n, ‖((k : ℂ)) ^ (-s)‖ := norm_sum_le _ _
    _ ≤ ∑ k ∈ Finset.Ico m n, (k : ℝ) ^ (-s.re) := Finset.sum_le_sum hB
    _ ≤ B := hsum

/-- **Complex Dirichlet partial sums, converged regime `Re s > 1`.**

`‖Σ_{k=m}^{N-1} k^{-s}‖ ≤ m^{1-σ}/(σ-1) + m^{-σ}`, uniform in `N`, for `σ = Re s > 1`, `m ≥ 1`.

This is the form a strip/zero-free-region argument quotes for the tail of a Dirichlet series in the
half-plane of absolute convergence. -/
theorem norm_sum_Ico_cpow_le_const {s : ℂ} (hσ : 1 < s.re)
    {m n : ℕ} (hm : 1 ≤ m) (hmn : m ≤ n) :
    ‖∑ k ∈ Finset.Ico m n, ((k : ℂ)) ^ (-s)‖
      ≤ (m : ℝ) ^ (1 - s.re) / (s.re - 1) + (m : ℝ) ^ (-s.re) :=
  norm_sum_Ico_cpow_le_of_sum_le
    (fun _k hk => (norm_cpow_neg_nat (le_trans hm (Finset.mem_Ico.mp hk).1)).le)
    (sum_Ico_rpow_le_const_of_one_lt hσ hm hmn)

/-- **Complex Dirichlet partial sums, explicit in `N`, regime `0 < Re s < 1`.**

`‖Σ_{k=m}^{N-1} k^{-s}‖ ≤ N^{1-σ}/(1-σ) + m^{-σ}`. No `N`-free version exists here: the sums grow
like `N^{1-σ}`. A strip argument keeps `N` explicit, typically `N ≈ |Im s|`. -/
theorem norm_sum_Ico_cpow_le_of_lt_one {s : ℂ} (hσ : 0 < s.re) (hσ1 : s.re < 1)
    {m n : ℕ} (hm : 1 ≤ m) (hmn : m ≤ n) :
    ‖∑ k ∈ Finset.Ico m n, ((k : ℂ)) ^ (-s)‖
      ≤ (n : ℝ) ^ (1 - s.re) / (1 - s.re) + (m : ℝ) ^ (-s.re) :=
  norm_sum_Ico_cpow_le_of_sum_le
    (fun _k hk => (norm_cpow_neg_nat (le_trans hm (Finset.mem_Ico.mp hk).1)).le)
    (sum_Ico_rpow_le_of_lt_one hσ hσ1 hm hmn)

end EulerMaclaurin
