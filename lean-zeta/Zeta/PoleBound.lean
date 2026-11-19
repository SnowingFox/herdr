/-
Copyright (c) 2026 Herdr contributors. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

public import Mathlib.NumberTheory.LSeries.RiemannZeta
public import Mathlib.Analysis.SumIntegralComparisons
public import Mathlib.Analysis.SpecialFunctions.ImproperIntegrals
public import Mathlib.Analysis.PSeriesComplex
public import Mathlib.NumberTheory.LSeries.Dirichlet
public import Mathlib.Analysis.PSeries

/-!
# The pole bound `Re ζ(σ) ≤ C / (σ - 1)` on `1 < σ ≤ 2`

The 3-4-1 inequality produces a factor `Re ζ(σ)³`, which blows up as `σ → 1⁺`. The rate of that
blow-up is what sets the shape of the zero-free region, so it must be pinned down quantitatively.

For `σ > 1`, `ζ(σ) = ∑_{n ≥ 1} n^{-σ} = 1 + ∑_{n ≥ 2} n^{-σ}`, and the integral test
(`AntitoneOn.tsum_comp_add_le_integral`) bounds the tail by `∫_1^∞ x^{-σ} dx = 1/(σ - 1)`:

  `ζ(σ) ≤ 1 + 1/(σ - 1)`.

Since `σ ≤ 2` gives `1 ≤ 1/(σ - 1)`, this yields `ζ(σ) ≤ 2/(σ - 1)`.

**The constant `2` is not claimed optimal.** The residue of `ζ` at `1` is `1`, so
`(σ - 1) ζ(σ) → 1` and no absolute constant below `1` can work as `σ → 1⁺`. `2` is what the
integral test gives directly on `1 < σ ≤ 2`; the 3-4-1 region is governed by the *rate* `1/(σ-1)`,
not by the constant.

## Main results

* `antitoneOn_rpow_neg` — `x ↦ x^{-σ}` is antitone on `[1, ∞)` for `σ > 0`.
* `tsum_tail_le_integral` — the integral test on the tail of the Dirichlet series.
* `zeta_re_eq_tsum` — `Re ζ(σ)` is the real Dirichlet series for real `σ > 1`.
* `zeta_re_le_inv_sub_one_add_one` — `Re ζ(σ) ≤ 1 + 1/(σ - 1)`.
* `zeta_re_le_two_div_sub_one` — `Re ζ(σ) ≤ 2/(σ - 1)` on `1 < σ ≤ 2` (the pole bound).
* `re_zeta_cube_le` — `Re ζ(σ)³ ≤ 8/(σ - 1)³`, the shape the 3-4-1 inequality consumes.
-/

@[expose] public section

open scoped BigOperators
open MeasureTheory

noncomputable section

namespace Zeta

/-! ### The integral test on the tail of the Dirichlet series -/

/-- `x ↦ x^{-σ}` is antitone on `[1, ∞)` for `σ > 0`. -/
theorem antitoneOn_rpow_neg {σ : ℝ} (hσ : 0 < σ) :
    AntitoneOn (fun x : ℝ => x ^ (-σ)) (Set.Ici (1 : ℝ)) := by
  intro x hx y _ hxy
  exact Real.rpow_le_rpow_of_nonpos (lt_of_lt_of_le one_pos hx) hxy (by linarith)

/-- **The integral test on the tail**: for `σ > 1`,
`∑_{n ≥ 0} (n + 2)^{-σ} ≤ ∫_1^∞ x^{-σ} dx = 1/(σ - 1)`. -/
theorem tsum_tail_le_integral {σ : ℝ} (hσ : 1 < σ) :
    ∑' n : ℕ, ((n : ℝ) + 2) ^ (-σ) ≤ 1 / (σ - 1) := by
  have hσpos : (0 : ℝ) < σ := by linarith
  have hone : (0 : ℝ) < ((1 : ℕ) : ℝ) := by norm_num
  have hanti : AntitoneOn (fun x : ℝ => x ^ (-σ)) (Set.Ici ((1 : ℕ) : ℝ)) := by
    intro x hx y _ hxy
    exact Real.rpow_le_rpow_of_nonpos (lt_of_lt_of_le hone hx) hxy (by linarith)
  have hnonneg : ∀ t ∈ Set.Ioi ((1 : ℕ) : ℝ), 0 ≤ t ^ (-σ) := by
    intro t ht
    have h1 : ((1 : ℕ) : ℝ) < t := ht
    exact Real.rpow_nonneg (le_of_lt (lt_trans hone h1)) _
  have hint : IntegrableOn (fun x : ℝ => x ^ (-σ)) (Set.Ioi ((1 : ℕ) : ℝ)) :=
    integrableOn_Ioi_rpow_of_lt (by linarith) hone
  have h : ∑' (n : ℕ), (↑(n + 1 + 1) : ℝ) ^ (-σ) ≤
      ∫ (x : ℝ) in Set.Ioi ((1 : ℕ) : ℝ), x ^ (-σ) :=
    AntitoneOn.tsum_comp_add_le_integral (f := fun x : ℝ => x ^ (-σ)) 1 hanti hint hnonneg
  have hval : ∫ x : ℝ in Set.Ioi ((1 : ℕ) : ℝ), x ^ (-σ) = 1 / (σ - 1) := by
    rw [integral_Ioi_rpow_of_lt (by linarith) hone]
    norm_num
    have h1 : (σ - 1) ≠ 0 := by linarith
    have h2 : (-σ + 1) ≠ 0 := by linarith
    field_simp
    ring
  rw [hval] at h
  have hcast : (∑' (n : ℕ), (↑(n + 1 + 1) : ℝ) ^ (-σ)) = ∑' n : ℕ, ((n : ℝ) + 2) ^ (-σ) := by
    refine tsum_congr fun n => ?_
    push_cast
    ring_nf
  rwa [hcast] at h

/-! ### `ζ` at a real point, as a real series -/

/-- **`Re ζ(σ)` is the real Dirichlet series** for real `σ > 1`. -/
theorem zeta_re_eq_tsum {σ : ℝ} (hσ : 1 < σ) :
    (riemannZeta (σ : ℂ)).re = ∑' n : ℕ, ((n : ℝ) + 1) ^ (-σ) := by
  have hc : riemannZeta (σ : ℂ) = ∑' n : ℕ, (1 : ℂ) / ((n : ℂ) + 1) ^ (σ : ℂ) :=
    zeta_eq_tsum_one_div_nat_add_one_cpow (by simpa using hσ)
  have hsum : Summable (fun n : ℕ => (1 : ℂ) / ((n : ℂ) + 1) ^ (σ : ℂ)) := by
    have hbase : Summable (fun n : ℕ => (1 : ℂ) / (n : ℂ) ^ (σ : ℂ)) :=
      (Complex.summable_one_div_nat_cpow (p := (σ : ℂ))).mpr (by simpa using hσ)
    have h2 := (summable_nat_add_iff 1).mpr hbase
    refine h2.congr fun n => ?_
    push_cast
    ring_nf
  rw [hc, Complex.re_tsum hsum]
  refine tsum_congr fun n => ?_
  have hx : (0 : ℝ) < (↑n : ℝ) + 1 := by positivity
  have hbase : ((n : ℂ) + 1) = (((n : ℝ) + 1 : ℝ) : ℂ) := by push_cast; ring
  rw [hbase, ← Complex.ofReal_cpow hx.le, ← Complex.ofReal_one, ← Complex.ofReal_div]
  rw [Complex.ofReal_re, Real.rpow_neg hx.le, one_div]

/-! ### The pole bound -/

/-- **`Re ζ(σ) ≤ 1 + 1/(σ - 1)`** for real `σ > 1`, from the integral test on the tail. -/
theorem zeta_re_le_inv_sub_one_add_one {σ : ℝ} (hσ : 1 < σ) :
    (riemannZeta (σ : ℂ)).re ≤ 1 + 1 / (σ - 1) := by
  rw [zeta_re_eq_tsum hσ]
  have hsummable : Summable (fun n : ℕ => ((n : ℝ) + 1) ^ (-σ)) := by
    have hbase : Summable (fun n : ℕ => (n : ℝ) ^ (-σ)) := by
      rw [Real.summable_nat_rpow]; linarith
    have h2 := (summable_nat_add_iff 1).mpr hbase
    exact h2.congr fun n => by push_cast; ring_nf
  rw [hsummable.tsum_eq_zero_add]
  have h0 : ((↑(0 : ℕ) : ℝ) + 1) ^ (-σ) = 1 := by norm_num
  rw [h0]
  have htail : (∑' n : ℕ, ((↑(n + 1) : ℝ) + 1) ^ (-σ))
      = ∑' n : ℕ, ((n : ℝ) + 2) ^ (-σ) := by
    refine tsum_congr fun n => ?_
    push_cast
    ring_nf
  rw [htail]
  have := tsum_tail_le_integral hσ
  linarith

/-- **The pole bound**: `Re ζ(σ) ≤ 2/(σ - 1)` for `1 < σ ≤ 2`. -/
theorem zeta_re_le_two_div_sub_one {σ : ℝ} (hσ : 1 < σ) (hσ2 : σ ≤ 2) :
    (riemannZeta (σ : ℂ)).re ≤ 2 / (σ - 1) := by
  have h := zeta_re_le_inv_sub_one_add_one hσ
  have hpos : 0 < σ - 1 := by linarith
  have hle : 1 ≤ 1 / (σ - 1) := by
    rw [le_div_iff₀ hpos]; linarith
  have h2 : 1 + 1 / (σ - 1) ≤ 2 / (σ - 1) := by
    rw [div_eq_mul_inv, div_eq_mul_inv] at *
    nlinarith
  linarith

/-- **`Re ζ(σ)³ ≤ 8/(σ - 1)³`** on `1 < σ ≤ 2`: the pole bound raised to the power the 3-4-1
inequality consumes. -/
theorem re_zeta_cube_le {σ : ℝ} (hσ : 1 < σ) (hσ2 : σ ≤ 2) :
    (riemannZeta (σ : ℂ)).re ^ 3 ≤ 8 / (σ - 1) ^ 3 := by
  have h := zeta_re_le_two_div_sub_one hσ hσ2
  have hpos : 0 < σ - 1 := by linarith
  have hnonneg : 0 ≤ (riemannZeta (σ : ℂ)).re :=
    le_of_lt (riemannZeta_re_pos_of_one_lt hσ)
  calc (riemannZeta (σ : ℂ)).re ^ 3 ≤ (2 / (σ - 1)) ^ 3 :=
        pow_le_pow_left₀ hnonneg h 3
    _ = 8 / (σ - 1) ^ 3 := by field_simp; ring

end Zeta
