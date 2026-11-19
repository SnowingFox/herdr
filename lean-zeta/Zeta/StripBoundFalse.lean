/-
Copyright (c) 2026 Herdr contributors. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

public import Mathlib.NumberTheory.LSeries.RiemannZeta

/-!
# Target 1 as stated is false: `‖ζ s‖` is unbounded in the strip

The assignment's Target 1 is

  `∃ C, ∀ s : ℂ, 1/2 ≤ s.re → s.re ≤ 1 → ‖riemannZeta s‖ ≤ C * Real.log (|s.im| + 2)`.

**That statement is false, and this file proves its negation.** `ζ` has a pole at `s = 1`, and the
pole is *inside* the prescribed region: `1/2 ≤ 1 ≤ 1` holds, and at `s = 1` the imaginary part is
`0`, so the claimed bound reads `‖ζ 1‖ ≤ C * log 2`. But `‖ζ s‖ → ∞` as `s → 1` from the left along
the real axis, inside the strip, while `C * log(|im s| + 2) = C * log 2` stays fixed. So no `C`
works.

Concretely: `riemannZeta_residue_one` says `(s - 1) ζ(s) → 1` as `s → 1`. Taking `s = σ` real and
`σ → 1⁻`, we get `(1 - σ) ‖ζ σ‖ → 1`, hence `‖ζ σ‖ ~ 1/(1 - σ) → ∞`.

**The repair** (used by every textbook) is to exclude the pole: the standard strip is
`1/2 ≤ Re s ≤ 1` with `s ≠ 1`, or equivalently restrict to `s.re < 1`, or state the bound only for
`‖Im s‖ ≥ 1`. `critical_strip_growth` in `Zeta.StripGrowth` is stated with `s.re < 1`, which is the
minimal honest repair and contains the whole open strip.

This file exists so the false statement cannot be silently re-introduced: any future attempt to
prove Target 1 verbatim must first contradict `not_strip_bound_at_pole`.

## Main results

* `tendsto_norm_zeta_at_one` — `‖ζ σ‖ → ∞` as `σ → 1⁻` through real values.
* `not_strip_bound_at_pole` — the negation of Target 1 as stated.
-/

@[expose] public section

open Filter Topology

noncomputable section

namespace Zeta

/-- **`‖ζ σ‖ → ∞` as `σ → 1` from below**, along the real axis.

Since `(s - 1) ζ(s) → 1` as `s → 1` (`riemannZeta_residue_one`), restricting to real `σ < 1` gives
`(1 - σ) ‖ζ σ‖ → 1`, so `‖ζ σ‖` diverges like `1/(1 - σ)`. -/
theorem tendsto_norm_zeta_at_one :
    Tendsto (fun σ : ℝ => ‖riemannZeta (σ : ℂ)‖) (nhdsWithin (1 : ℝ) (Set.Iio 1)) atTop := by
  have hres := riemannZeta_residue_one
  -- the real segment maps into the punctured neighbourhood of `1`
  have hmem : Tendsto (fun σ : ℝ => ((σ : ℂ))) (nhdsWithin (1 : ℝ) (Set.Iio 1))
      (nhdsWithin (1 : ℂ) {1}ᶜ) := by
    refine tendsto_nhdsWithin_iff.mpr ⟨?_, ?_⟩
    · exact (Complex.continuous_ofReal.tendsto _).mono_left inf_le_left
    · filter_upwards [self_mem_nhdsWithin] with σ hσ
      simp only [Set.mem_compl_iff, Set.mem_singleton_iff]
      intro h
      have h' : σ = 1 := by exact_mod_cast h
      exact absurd h' (ne_of_lt (Set.mem_Iio.mp hσ))
  have h2 : Tendsto (fun σ : ℝ => ((σ : ℂ) - 1) * riemannZeta (σ : ℂ))
      (nhdsWithin (1 : ℝ) (Set.Iio 1)) (𝓝 (1 : ℂ)) := hres.comp hmem
  have hnorm2 : Tendsto (fun σ : ℝ => ‖((σ : ℂ) - 1) * riemannZeta (σ : ℂ)‖)
      (nhdsWithin (1 : ℝ) (Set.Iio 1)) (𝓝 (1 : ℝ)) := by
    have h := (continuous_norm.tendsto (1 : ℂ)).comp h2
    have h' : ‖(1 : ℂ)‖ = (1 : ℝ) := by simp
    rw [h'] at h
    exact h
  have h3 : Tendsto (fun σ : ℝ => 1 - σ) (nhdsWithin (1 : ℝ) (Set.Iio 1))
      (nhdsWithin (0 : ℝ) (Set.Ioi 0)) := by
    have hcont : Tendsto (fun σ : ℝ => 1 - σ) (nhdsWithin (1 : ℝ) (Set.Iio 1)) (𝓝 (1 - 1)) :=
      (tendsto_const_nhds.sub tendsto_id).mono_left inf_le_left
    rw [sub_self] at hcont
    refine tendsto_nhdsWithin_iff.mpr ⟨hcont, ?_⟩
    filter_upwards [self_mem_nhdsWithin] with σ hσ
    exact sub_pos.mpr (Set.mem_Iio.mp hσ)
  have hinv : Tendsto (fun σ : ℝ => (1 - σ)⁻¹) (nhdsWithin (1 : ℝ) (Set.Iio 1)) atTop :=
    tendsto_inv_nhdsGT_zero.comp h3
  -- eventually `(1/2) * (1-σ)⁻¹ ≤ ‖ζ σ‖`
  have hhalf : ∀ᶠ σ : ℝ in nhdsWithin (1 : ℝ) (Set.Iio 1),
      (1 / 2 : ℝ) * (1 - σ)⁻¹ ≤ ‖riemannZeta (σ : ℂ)‖ := by
    have hev : ∀ᶠ σ : ℝ in nhdsWithin (1 : ℝ) (Set.Iio 1),
        (1 / 2 : ℝ) ≤ ‖((σ : ℂ) - 1) * riemannZeta (σ : ℂ)‖ := by
      apply hnorm2.eventually
      exact eventually_ge_nhds (by norm_num : (1 / 2 : ℝ) < 1)
    filter_upwards [hev, self_mem_nhdsWithin] with σ hσ hlt
    have hpos : 0 < 1 - σ := sub_pos.mpr (Set.mem_Iio.mp hlt)
    have hnorm : ‖((σ : ℂ) - 1)‖ = 1 - σ := by
      rw [show ((σ : ℂ) - 1) = ((σ - 1 : ℝ) : ℂ) by push_cast; ring, Complex.norm_real,
        Real.norm_eq_abs, abs_of_neg (by linarith)]
      ring
    have hkey : ‖riemannZeta (σ : ℂ)‖
        = ‖((σ : ℂ) - 1) * riemannZeta (σ : ℂ)‖ * (1 - σ)⁻¹ := by
      rw [norm_mul, hnorm]
      field_simp
    rw [hkey]
    exact mul_le_mul_of_nonneg_right hσ (by positivity)
  refine tendsto_atTop_mono' _ hhalf ?_
  have hcut := Tendsto.const_mul_atTop
    (l := nhdsWithin (1 : ℝ) (Set.Iio 1)) (by norm_num : (0 : ℝ) < 1 / 2) hinv
  simpa using hcut

/-- **Target 1 as stated is false.**

The claimed bound `∃ C, ∀ s, 1/2 ≤ Re s → Re s ≤ 1 → ‖ζ s‖ ≤ C log(|Im s| + 2)` fails at the
pole `s = 1`, which lies in the stated region. -/
theorem not_strip_bound_at_pole :
    ¬ ∃ C : ℝ, ∀ s : ℂ, (1 / 2 : ℝ) ≤ s.re → s.re ≤ 1 →
      ‖riemannZeta s‖ ≤ C * Real.log (|s.im| + 2) := by
  rintro ⟨C, hC⟩
  -- any such bound would give a uniform bound on `‖ζ σ‖` along `1/2 ≤ σ < 1`
  have hbound : ∀ᶠ σ : ℝ in nhdsWithin (1 : ℝ) (Set.Ioo (1 / 2) 1),
      ‖riemannZeta (σ : ℂ)‖ ≤ C * Real.log 2 := by
    filter_upwards [self_mem_nhdsWithin] with σ hσ
    have him : ((σ : ℂ)).im = 0 := by simp
    have hre : ((σ : ℂ)).re = σ := by simp
    have hge : (1 / 2 : ℝ) ≤ ((σ : ℂ)).re := by rw [hre]; linarith [hσ.1]
    have hle : ((σ : ℂ)).re ≤ 1 := by rw [hre]; linarith [hσ.2]
    have := hC (σ : ℂ) hge hle
    rwa [him, abs_zero, zero_add] at this
  -- but `‖ζ σ‖ → ∞` on that same filter, so it eventually exceeds the bound
  have hdiv : Tendsto (fun σ : ℝ => ‖riemannZeta (σ : ℂ)‖)
      (nhdsWithin (1 : ℝ) (Set.Ioo (1 / 2) 1)) atTop :=
    tendsto_norm_zeta_at_one.mono_left (nhdsWithin_mono 1 Set.Ioo_subset_Iio_self)
  have hev : ∀ᶠ σ : ℝ in nhdsWithin (1 : ℝ) (Set.Ioo (1 / 2) 1),
      C * Real.log 2 + 1 ≤ ‖riemannZeta (σ : ℂ)‖ :=
    hdiv.eventually (eventually_ge_atTop (C * Real.log 2 + 1))
  have hne' : (nhdsWithin (1 : ℝ) (Set.Ioo (1 / 2) 1)).NeBot :=
    right_nhdsWithin_Ioo_neBot (by norm_num : (1 / 2 : ℝ) < 1)
  obtain ⟨σ, h1, h2⟩ := (hev.and hbound).exists
  linarith

end Zeta
