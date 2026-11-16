/-
Copyright (c) 2026 Herdr contributors. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

public import Mathlib.NumberTheory.LSeries.Nonvanishing
public import Mathlib.NumberTheory.EulerProduct.DirichletLSeries
public import Mathlib.Analysis.PSeriesComplex
public import Mathlib.Analysis.SumIntegralComparisons

/-!
# The 3-4-1 inequality for the Riemann zeta function

The classical de la Vallée Poussin argument starts from the pointwise inequality
`0 ≤ 3 + 4 cos θ + cos 2θ` (`Zeta.three_add_four_cos_add_cos_two`). Applied to the
logarithm of the Euler product at the three points `1 + x`, `1 + x + i y`,
`1 + x + 2 i y`, it yields the norm bound

`‖ζ(1+x)^3 * ζ(1+x+iy)^4 * ζ(1+x+2iy)‖ ≥ 1`   (`x > 0`),

which is `Zeta.riemannZeta_norm_product_ge_one`.

Mathlib proves the general form for Dirichlet characters as
`DirichletCharacter.norm_LSeries_product_ge_one`; here it is specialised to `riemannZeta`.

We then extract the analytic comparisons that a de la Vallée Poussin zero-free region uses,
and record the reciprocal fourth-power bound that is the direct functional consequence of
the product inequality.

## Main results

* `Zeta.three_add_four_cos_add_cos_two` : the elementary trigonometric inequality.
* `Zeta.riemannZeta_norm_product_ge_one` : the 3-4-1 inequality for `ζ`.
* `Zeta.riemannZeta_norm_le_re` : `‖ζ s‖ ≤ Re ζ(σ)` for `σ = Re s > 1`.
* `Zeta.riemannZeta_inv_norm_ge_inv_re` : `1/Re ζ(σ) ≤ ‖1/ζ s‖` for `σ = Re s > 1`.
* `Zeta.riemannZeta_inv_pow_le` : `‖1/ζ(σ+it)‖⁴ ≤ Re ζ(σ)³ * ‖ζ(σ+2it)‖` for `σ > 1`.
-/

@[expose] public section

open Complex
open scoped LSeries.notation

namespace Zeta

/-! ### Real and imaginary parts of `σ + c * I * t` -/

theorem re_add_two_mul_I_mul (σ t : ℝ) : ((σ:ℂ) + 2 * Complex.I * (t:ℂ)).re = σ := by
  have h : (2:ℂ) * Complex.I * (t:ℂ) = ((2*t : ℝ) : ℂ) * Complex.I := by
    rw [mul_assoc]; push_cast; ring
  rw [h, Complex.add_re, Complex.ofReal_re, Complex.mul_re, Complex.ofReal_re,
    Complex.ofReal_im, Complex.I_re, Complex.I_im]
  ring

theorem im_add_two_mul_I_mul (σ t : ℝ) : ((σ:ℂ) + 2 * Complex.I * (t:ℂ)).im = 2 * t := by
  have h : (2:ℂ) * Complex.I * (t:ℂ) = ((2*t : ℝ) : ℂ) * Complex.I := by
    rw [mul_assoc]; push_cast; ring
  rw [h, Complex.add_im, Complex.ofReal_im, Complex.mul_im, Complex.ofReal_re,
    Complex.ofReal_im, Complex.I_re, Complex.I_im]
  ring

theorem re_add_one_mul_I_mul (σ t : ℝ) : ((σ:ℂ) + Complex.I * (t:ℂ)).re = σ := by
  have h : Complex.I * (t:ℂ) = ((t : ℝ) : ℂ) * Complex.I := by rw [mul_comm]
  rw [h, Complex.add_re, Complex.ofReal_re, Complex.mul_re, Complex.ofReal_re,
    Complex.ofReal_im, Complex.I_re, Complex.I_im]
  ring

/-! ### The elementary trigonometric inequality -/

/-- **The `3 + 4 cos θ + cos 2θ ≥ 0` inequality.** This is the pointwise input to the
3-4-1 argument, following from `cos 2θ = 2 cos²θ - 1` and `cos θ ≥ -1`. -/
theorem three_add_four_cos_add_cos_two (θ : ℝ) : 0 ≤ 3 + 4 * Real.cos θ + Real.cos (2 * θ) := by
  have h2 : Real.cos (2 * θ) = 2 * Real.cos θ ^ 2 - 1 := Real.cos_two_mul θ
  have hb : -1 ≤ Real.cos θ := Real.neg_one_le_cos θ
  nlinarith [sq_nonneg (Real.cos θ + 1), h2, hb]

/-! ### Specialising the Euler-product 3-4-1 bound to `ζ` -/

/-- For the principal character of level `1`, the L-series agrees with the L-series of the
constant sequence `1`. -/
theorem LSeries_one_eq (s : ℂ) :
    L ↗(1 : DirichletCharacter ℂ 1) s = L (1 : ℕ → ℂ) s := by
  rw [LSeries_congr]
  intro n _
  simp

/-- **The 3-4-1 inequality for `riemannZeta`.**
For `x > 0` and any real `y`,
`‖ζ(1+x)^3 * ζ(1+x+iy)^4 * ζ(1+x+2iy)‖ ≥ 1`. -/
theorem riemannZeta_norm_product_ge_one {x : ℝ} (hx : 0 < x) (y : ℝ) :
    1 ≤ ‖riemannZeta (1 + x) ^ 3 * riemannZeta (1 + x + I * y) ^ 4 *
          riemannZeta (1 + x + 2 * I * y)‖ := by
  have h := DirichletCharacter.norm_LSeries_product_ge_one (1 : DirichletCharacter ℂ 1) hx y
  have e1 : L ↗(1 : DirichletCharacter ℂ 1) (1 + x) = riemannZeta (1 + x) := by
    rw [LSeries_one_eq]; exact LSeries_one_eq_riemannZeta (by simp; linarith)
  have e2 : L ↗(1 : DirichletCharacter ℂ 1) (1 + x + I * y) = riemannZeta (1 + x + I * y) := by
    rw [LSeries_one_eq]; exact LSeries_one_eq_riemannZeta (by simp; linarith)
  have e3 : L ↗((1 : DirichletCharacter ℂ 1) ^ 2 :) (1 + x + 2 * I * y)
      = riemannZeta (1 + x + 2 * I * y) := by
    rw [show L ↗((1 : DirichletCharacter ℂ 1) ^ 2 :) (1 + x + 2 * I * y)
        = L ↗(1 : DirichletCharacter ℂ 1) (1 + x + 2 * I * y) from by
      rw [LSeries_congr]; intro n _; simp]
    rw [LSeries_one_eq]; exact LSeries_one_eq_riemannZeta (by simp; linarith)
  rw [e1, e2, e3] at h
  simpa using h

/-! ### Comparison of `‖ζ s‖` with `Re ζ(σ)` -/

/-- The `n`-th Dirichlet term of `ζ` at a real point `σ` is the coercion of a real number. -/
theorem term_real (σ : ℝ) (n : ℕ) :
    (1 : ℂ) / ((n : ℂ) + 1) ^ (σ : ℂ) = (((1 / ((n : ℝ) + 1) ^ σ : ℝ)) : ℂ) := by
  have hx : (0:ℝ) ≤ (n : ℝ) + 1 := by positivity
  rw [show ((n : ℂ) + 1) = (((n : ℝ) + 1 : ℝ) : ℂ) by push_cast; ring]
  rw [← Complex.ofReal_cpow hx σ, Complex.ofReal_div, Complex.ofReal_one]

/-- The shifted series `∑' n, 1/(n+1)^σ` is summable for `σ > 1`. -/
theorem summable_shift (σ : ℝ) (h : 1 < σ) :
    Summable (fun n : ℕ => (1:ℂ) / ((n : ℂ) + 1) ^ (σ:ℂ)) := by
  have hbase : Summable (fun n : ℕ => (1:ℂ) / (n : ℂ) ^ (σ:ℂ)) :=
    (Complex.summable_one_div_nat_cpow (p := (σ:ℂ))).mpr (by simpa using h)
  have := (summable_nat_add_iff (f := fun n : ℕ => (1:ℂ) / (n : ℂ) ^ (σ:ℂ)) 1).mpr hbase
  refine this.congr (fun n => ?_)
  push_cast; ring_nf

/-- **Comparison of `‖ζ s‖` with `Re ζ(σ)`.** For `σ = Re s > 1`, `‖ζ s‖ ≤ Re ζ(σ)`. -/
theorem riemannZeta_norm_le_re {s : ℂ} (hs : 1 < s.re) :
    ‖riemannZeta s‖ ≤ (riemannZeta (s.re : ℂ)).re := by
  set σ := s.re with hσ
  have hσ1 : 1 < σ := hs
  have hζ : riemannZeta (σ : ℂ) = ∑' n : ℕ, 1 / ((n : ℂ) + 1) ^ (σ : ℂ) :=
    zeta_eq_tsum_one_div_nat_add_one_cpow (by simpa using hs)
  have hζs : riemannZeta s = ∑' n : ℕ, 1 / ((n : ℂ) + 1) ^ s :=
    zeta_eq_tsum_one_div_nat_add_one_cpow hs
  have hnorm : Summable (fun n : ℕ => ‖1 / ((n : ℂ) + 1) ^ s‖) := by
    have hbase : Summable (fun n : ℕ => 1 / (n : ℂ) ^ s) :=
      (Complex.summable_one_div_nat_cpow (p := s)).mpr hs
    have hsh := (summable_nat_add_iff (f := fun n : ℕ => 1 / (n : ℂ) ^ s) 1).mpr hbase
    refine hsh.norm.congr (fun n => ?_)
    push_cast; ring_nf
  have hreal : ∀ n : ℕ, ‖1 / ((n : ℂ) + 1) ^ s‖ = (1 / ((n : ℂ) + 1) ^ (σ : ℂ)).re := by
    intro n
    rw [term_real σ n, Complex.ofReal_re]
    rw [show ((n : ℂ) + 1) = (((n : ℝ) + 1 : ℝ) : ℂ) by push_cast; ring]
    rw [norm_div, norm_one, Complex.norm_cpow_eq_rpow_re_of_pos (by positivity)]
  rw [hζs, hζ, Complex.re_tsum (summable_shift σ hσ1)]
  calc ‖∑' n : ℕ, 1 / ((n : ℂ) + 1) ^ s‖
      ≤ ∑' n : ℕ, ‖1 / ((n : ℂ) + 1) ^ s‖ := norm_tsum_le_tsum_norm hnorm
    _ = ∑' n : ℕ, (1 / ((n : ℂ) + 1) ^ (σ : ℂ)).re := by
        congr 1 with n; exact hreal n

/-- **Reciprocal comparison.** For `σ = Re s > 1`, `1 / Re ζ(σ) ≤ ‖1 / ζ s‖`. -/
theorem riemannZeta_inv_norm_ge_inv_re {s : ℂ} (hs : 1 < s.re) :
    1 / (riemannZeta (s.re : ℂ)).re ≤ ‖(riemannZeta s)⁻¹‖ := by
  have hnorm : 0 < ‖riemannZeta s‖ := by
    rw [norm_pos_iff]; exact riemannZeta_ne_zero_of_one_lt_re hs
  rw [norm_inv]
  simpa only [one_div] using inv_anti₀ hnorm (riemannZeta_norm_le_re hs)

/-- **The value of `ζ` at a real point is real and positive for `σ > 1`.** -/
theorem norm_riemannZeta_ofReal {σ : ℝ} (hσ : 1 < σ) :
    ‖riemannZeta (σ:ℂ)‖ = (riemannZeta (σ:ℂ)).re := by
  obtain ⟨h1, h2⟩ := Complex.pos_iff.mp (riemannZeta_pos_of_one_lt hσ)
  have him : (riemannZeta (σ:ℂ)).im = 0 := h2.symm
  simp only [Complex.norm_def, Complex.normSq_apply, him, mul_zero, add_zero]
  rw [Real.sqrt_mul_self h1.le]

/-! ### The reciprocal fourth-power bound -/

/-- **The reciprocal fourth-power bound.** For `σ > 1` and real `t`,
`‖1/ζ(σ+it)‖⁴ ≤ Re ζ(σ)³ * ‖ζ(σ+2it)‖`.

This is the 3-4-1 inequality rewritten using `riemannZeta_norm_product_ge_one`. It is the
form in which the argument feeds into a zero-free region. -/
theorem riemannZeta_inv_pow_le {σ t : ℝ} (hσ : 1 < σ) :
    ‖(riemannZeta ((σ:ℂ) + I * (t:ℂ)))⁻¹‖ ^ 4 ≤
      (riemannZeta (σ:ℂ)).re ^ 3 * ‖riemannZeta ((σ:ℂ) + 2 * I * (t:ℂ))‖ := by
  have h := riemannZeta_norm_product_ge_one (x := σ - 1) (by linarith) (y := t)
  simp only [Complex.ofReal_sub, Complex.ofReal_one] at h
  rw [show ((1:ℂ) + ((σ:ℝ) - 1)) = (σ:ℂ) by ring] at h
  rw [norm_mul, norm_mul, norm_pow, norm_pow, norm_riemannZeta_ofReal hσ] at h
  have hre2 : ((σ:ℂ) + 2 * I * (t:ℂ)).re = σ := re_add_two_mul_I_mul σ t
  have hre1 : ((σ:ℂ) + I * (t:ℂ)).re = σ := re_add_one_mul_I_mul σ t
  have hz : 0 < (riemannZeta (σ:ℂ)).re := riemannZeta_re_pos_of_one_lt hσ
  have hnorm2 : 0 < ‖riemannZeta ((σ:ℂ) + 2 * I * (t:ℂ))‖ := by
    rw [norm_pos_iff]; exact riemannZeta_ne_zero_of_one_lt_re (by rw [hre2]; exact hσ)
  have hnorm1 : 0 < ‖riemannZeta ((σ:ℂ) + I * (t:ℂ))‖ := by
    rw [norm_pos_iff]; exact riemannZeta_ne_zero_of_one_lt_re (by rw [hre1]; exact hσ)
  have hd : 0 < (riemannZeta (σ:ℂ)).re ^ 3 * ‖riemannZeta ((σ:ℂ) + 2 * I * (t:ℂ))‖ := by
    positivity
  rw [norm_inv]
  -- goal: (‖ζ(σ+it)‖⁻¹)^4 ≤ Re ζ(σ)^3 * ‖ζ(σ+2it)‖
  -- rewrite LHS as (‖ζ(σ+it)‖^4)⁻¹ and clear denominators
  have h4 : 0 < ‖riemannZeta ((σ:ℂ) + I * (t:ℂ))‖ ^ 4 := pow_pos hnorm1 4
  rw [inv_pow, ← one_div, div_le_iff₀ h4]
  -- goal: 1 ≤ (Re ζ(σ)^3 * ‖ζ(σ+2it)‖) * ‖ζ(σ+it)‖^4
  nlinarith [h, mul_pos hd h4, h4]
