/-
Copyright (c) 2026 Herdr contributors. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

public import Mathlib.NumberTheory.LSeries.ZetaZeros
public import Mathlib.NumberTheory.LSeries.Nonvanishing
public import Mathlib.Analysis.Complex.Basic

/-!
# A height-local zero-free region for the Riemann zeta function

This file records what follows from Mathlib's existing facts about `ζ` *without* any
Euler–Maclaurin growth estimates.

The honest content is:

* zeros of `ζ` are discrete, so any compact set contains finitely many of them
  (`IsCompact.inter_riemannZetaZeros_finite`);
* `ζ` does not vanish on `Re s ≥ 1` (`riemannZeta_ne_zero_of_one_le_re`).

Combining these gives a genuine zero-free region that **crosses** the line `Re s = 1`, but only
on a bounded height window, with the width constant depending on the window. This is
`Zeta.exists_zero_free_height_local`.

## What this is and is not

The constant `c` produced below depends on the height bound `H`. The classical de la Vallée
Poussin region

`∃ c > 0, ∀ s, 1 - c / log (|s.im| + 2) < s.re → ζ s ≠ 0`

with `c` **absolute** cannot be obtained from compactness alone: the constant must deteriorate as
`H → ∞` because zeros become denser. Closing that gap requires quantitative growth bounds on `ζ`
in the critical strip which Mathlib does not currently provide:

* `‖ζ(σ + it)‖ ≤ C log(|t| + 2)` uniformly for `σ ≥ 1/2` (Euler–Maclaurin / integral test);
* `Re ζ(σ) ≤ C / (σ - 1)` for `σ ∈ (1, 2)` (integral test against `t^{-σ}`);
* a local bound `‖ζ(σ + iγ)‖ ≤ C‖σ - β‖` at a zero `β + iγ`.

The 3-4-1 inequality needed to consume these is in module `Zeta.ThreeFourOne`
(`Zeta.riemannZeta_inv_pow_le`).

## Main results

* `Zeta.isCompact_strip`
* `Zeta.exists_zero_free_height_local`
-/

@[expose] public section

open Complex Set

namespace Zeta

/-- The closed strip `1/2 ≤ Re s ≤ 1`, `|Im s| ≤ H` is bounded. -/
theorem strip_bounded (H : ℝ) :
    Bornology.IsBounded {s : ℂ | (1/2 : ℝ) ≤ s.re ∧ s.re ≤ 1 ∧ |s.im| ≤ H} := by
  refine Bornology.IsBounded.subset (Metric.isBounded_closedBall (x := 0) (r := 2 + H)) ?_
  intro s hs
  simp only [Set.mem_ofPred_eq] at hs
  obtain ⟨h1, h2, h3⟩ := hs
  have him1 : -H ≤ s.im := (abs_le.mp h3).1
  have him2 : s.im ≤ H := (abs_le.mp h3).2
  have hH : 0 ≤ H := by linarith
  simp only [Metric.mem_closedBall, dist_zero_right, Complex.norm_def]
  have hnormSq : Complex.normSq s = s.re * s.re + s.im * s.im := rfl
  rw [hnormSq]
  have hre2 : s.re * s.re ≤ 1 := by nlinarith
  have him2' : s.im * s.im ≤ H * H := by nlinarith
  have hbound : s.re * s.re + s.im * s.im ≤ (2 + H) * (2 + H) := by nlinarith
  have h2H : (0:ℝ) ≤ 2 + H := by linarith
  calc Real.sqrt (s.re * s.re + s.im * s.im) ≤ Real.sqrt ((2+H)*(2+H)) := Real.sqrt_le_sqrt hbound
    _ = 2 + H := Real.sqrt_mul_self h2H

/-- The closed strip `1/2 ≤ Re s ≤ 1`, `|Im s| ≤ H` is compact. -/
theorem isCompact_strip (H : ℝ) :
    IsCompact {s : ℂ | (1/2 : ℝ) ≤ s.re ∧ s.re ≤ 1 ∧ |s.im| ≤ H} := by
  have hcont : Continuous fun s : ℂ => (s.re, s.im) := continuous_re.prodMk continuous_im
  have hset : {s : ℂ | (1/2 : ℝ) ≤ s.re ∧ s.re ≤ 1 ∧ |s.im| ≤ H}
      = (fun s : ℂ => (s.re, s.im)) ⁻¹'
        (Set.Icc (1/2 : ℝ) 1 ×ˢ Set.Icc (-H) H) := by
    ext s
    simp only [Set.mem_preimage, Set.mem_prod, Set.mem_Icc, Set.mem_ofPred_eq, abs_le]
    constructor
    · rintro ⟨h1, h2, h3, h4⟩; exact ⟨⟨h1, h2⟩, h3, h4⟩
    · rintro ⟨⟨h1, h2⟩, h3, h4⟩; exact ⟨h1, h2, h3, h4⟩
  rw [Metric.isCompact_iff_isClosed_bounded, hset]
  exact ⟨(isClosed_Icc.prod isClosed_Icc).preimage hcont, hset ▸ strip_bounded H⟩

/-- **Height-local zero-free region.** For every height bound `H ≥ 0` there is `c > 0` such that
`ζ s ≠ 0` whenever `|s.im| ≤ H` and `1 - c / log (|s.im| + 2) < s.re`.

The constant `c` depends on `H`; see the module docstring. -/
theorem exists_zero_free_height_local (H : ℝ) :
    ∃ c : ℝ, 0 < c ∧ ∀ s : ℂ, |s.im| ≤ H →
      1 - c / Real.log (|s.im| + 2) < s.re → riemannZeta s ≠ 0 := by
  set S : Set ℂ := {s : ℂ | (1/2 : ℝ) ≤ s.re ∧ s.re ≤ 1 ∧ |s.im| ≤ H} ∩ riemannZetaZeros with hS
  have hfin : S.Finite := isCompact_strip H |>.inter_riemannZetaZeros_finite
  classical
  -- every zero in the strip has `Re ρ < 1`
  have hlt : ∀ ρ ∈ S, ρ.re < 1 := by
    intro ρ hρ
    obtain ⟨-, hz⟩ := hρ
    rw [mem_riemannZetaZeros] at hz
    by_contra hcon
    exact riemannZeta_ne_zero_of_one_le_re (by linarith) hz
  -- the gap `1 - Re ρ` is positive on the finite zero set
  obtain ⟨g, hgpos, hgle⟩ : ∃ g : ℝ, 0 < g ∧ ∀ ρ ∈ S, g ≤ 1 - ρ.re := by
    rcases Set.eq_empty_or_nonempty S with hemp | hne
    · exact ⟨1, one_pos, by simp [hemp]⟩
    · -- the maximum of `Re ρ` over the finite set `S`
      obtain ⟨ρ₀, hρ₀⟩ := hne
      set m : ℝ := hfin.toFinset.sup' (hfin.toFinset_nonempty.mpr ⟨ρ₀, hρ₀⟩)
        (fun ρ => ρ.re) with hm
      have hm_ub : ∀ ρ ∈ S, ρ.re ≤ m := by
        intro ρ hρ
        exact Finset.le_sup' _ (by simpa using hρ)
      have hm_lt : m < 1 := by
        rw [hm]
        exact Finset.sup'_lt_iff _ |>.mpr (fun ρ hρ => hlt ρ (by simpa using hρ))
      exact ⟨1 - m, by linarith, fun ρ hρ => by linarith [hm_ub ρ hρ]⟩
  refine ⟨min (g * Real.log 2) (Real.log 2 / 2), ?_, ?_⟩
  · refine lt_min ?_ ?_
    · have : 0 < Real.log 2 := Real.log_pos (by norm_num)
      positivity
    · have : 0 < Real.log 2 := Real.log_pos (by norm_num)
      positivity
  intro s hHim hsr hz0
  have hlog2 : 0 < Real.log 2 := Real.log_pos (by norm_num)
  have hlogpos : 0 < Real.log (|s.im| + 2) :=
    Real.log_pos (by have : (0:ℝ) ≤ |s.im| := abs_nonneg _; linarith)
  have hlogmono : Real.log 2 ≤ Real.log (|s.im| + 2) :=
    Real.log_le_log (by norm_num) (by have : (0:ℝ) ≤ |s.im| := abs_nonneg _; linarith)
  have hc_le2 : min (g * Real.log 2) (Real.log 2 / 2) ≤ g * Real.log 2 := min_le_left _ _
  have hc_le1 : min (g * Real.log 2) (Real.log 2 / 2) ≤ Real.log 2 / 2 := min_le_right _ _
  -- `s.re > 1/2`
  have hhalf : (1/2 : ℝ) ≤ s.re := by
    have : min (g * Real.log 2) (Real.log 2 / 2) / Real.log (|s.im| + 2) ≤ 1 / 2 := by
      rw [div_le_iff₀ hlogpos]; nlinarith
    linarith
  -- `s.re ≤ 1`, since otherwise nonvanishing gives a contradiction
  have hle1 : s.re ≤ 1 := by
    by_contra hcon
    exact riemannZeta_ne_zero_of_one_le_re (by linarith) hz0
  -- so `s` is one of the zeros in the strip
  have hmem : s ∈ S := ⟨⟨hhalf, hle1, hHim⟩, by rwa [mem_riemannZetaZeros]⟩
  have hgle' := hgle s hmem
  -- the region condition, together with `c/log ≤ g`, forces `s.re > 1 - g`
  have hcle : min (g * Real.log 2) (Real.log 2 / 2) / Real.log (|s.im| + 2) ≤ g := by
    rw [div_le_iff₀ hlogpos]
    nlinarith [hc_le2, hlogmono, hgpos.le, hlog2]
  have hone : 1 - g < s.re := by linarith
  -- ... but a zero in the strip satisfies `s.re ≤ 1 - g`
  linarith

/-- **Constant-width height-local zero-free region.** For every height bound `H` there is `δ > 0`
such that `ζ s ≠ 0` whenever `|s.im| ≤ H` and `1 - δ < s.re`.

This follows from `exists_zero_free_height_local`: on `|s.im| ≤ H` the quantity
`c / log(|s.im| + 2)` is bounded below by `c / log(H + 2)`. The constant `δ` still depends on
`H`; an absolute `δ`, equivalently an absolute `c` in the `1 - c/log` shape, is not obtainable
from compactness (see the module docstring). -/
theorem exists_zero_free_strip_height_local (H : ℝ) :
    ∃ δ : ℝ, 0 < δ ∧ ∀ s : ℂ, |s.im| ≤ H → 1 - δ < s.re → riemannZeta s ≠ 0 := by
  rcases lt_or_ge H 0 with hHneg | hH
  · -- `|s.im| ≤ H < 0` is impossible, so the region is empty
    exact ⟨1, one_pos, fun s hHim _ => absurd hHim (by
      have := abs_nonneg s.im; linarith)⟩
  obtain ⟨c, hc, hregion⟩ := exists_zero_free_height_local H
  have hlogH : 0 < Real.log (H + 2) := Real.log_pos (by linarith)
  refine ⟨c / Real.log (H + 2), div_pos hc hlogH, ?_⟩
  intro s hHim hsr
  apply hregion s hHim
  -- `c / log(|s.im| + 2) ≥ c / log(H + 2) = δ`
  have hlogpos : 0 < Real.log (|s.im| + 2) := by
    apply Real.log_pos; nlinarith [abs_nonneg s.im]
  have hlogmono : Real.log (|s.im| + 2) ≤ Real.log (H + 2) := by
    apply Real.log_le_log (by positivity)
    linarith [(abs_le.mp hHim).2]
  have : c / Real.log (H + 2) ≤ c / Real.log (|s.im| + 2) :=
    div_le_div_of_nonneg_left hc.le hlogpos hlogmono
  linarith

end Zeta
