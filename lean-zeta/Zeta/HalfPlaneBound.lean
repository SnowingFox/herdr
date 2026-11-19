/-
Copyright (c) 2026 Herdr contributors. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

public import Zeta.PoleBound
public import Zeta.ThreeFourOne

/-!
# Uniform-in-height growth on the half-plane of convergence

The pole bound (`Zeta.PoleBound`) bounds `Re ζ(σ)` on the real axis. The 3-4-1 engine
(`Zeta.ThreeFourOne`) supplies `‖ζ s‖ ≤ Re ζ(Re s)` whenever `Re s > 1`. Composing them gives a
bound on `‖ζ(σ + it)‖` that is **uniform in `t`**:

  `1 < σ ≤ 2 → ‖ζ(σ + it)‖ ≤ 2 / (σ - 1)`   for every real `t`.

This is the exact shape a 3-4-1 zero-free-region argument consumes for the "far right" factor
`ζ(σ + 2it)`: it says that factor is controlled by `1/(σ-1)` alone, with no dependence on the
height. It is the quantitative form of "ζ is bounded on compact subsets of `Re s > 1`", made
explicit.

Note the honest limitation: this is a bound on `Re s > 1` only. It says nothing about the critical
strip `1/2 ≤ Re s ≤ 1`, where the Dirichlet series does not converge and `‖ζ s‖` genuinely grows
like `log |Im s|`. That strip bound is the open target (`Zeta.StripBoundFalse` documents why the
naive statement of it is false).

## Main results

* `norm_zeta_le_two_div_sub_one` — `‖ζ(σ + it)‖ ≤ 2/(σ-1)` for `1 < σ ≤ 2`, uniformly in `t`.
* `norm_zeta_le_of_one_lt_re` — the same for an arbitrary complex `s` in terms of `s.re`.
-/

@[expose] public section

open Complex

noncomputable section

namespace Zeta

/-- **Uniform-in-height bound on the half-plane of convergence.**

For `1 < σ ≤ 2` and any real `t`, `‖ζ(σ + it)‖ ≤ 2/(σ - 1)`.

The right-hand side does not mention `t`: the height enters only through the requirement
`Re (σ + it) = σ > 1`, where the Dirichlet series converges absolutely. -/
theorem norm_zeta_le_two_div_sub_one {σ t : ℝ} (hσ : 1 < σ) (hσ2 : σ ≤ 2) :
    ‖riemannZeta ((σ : ℂ) + Complex.I * (t : ℂ))‖ ≤ 2 / (σ - 1) := by
  have hre : ((σ : ℂ) + Complex.I * (t : ℂ)).re = σ := by
    simp [Complex.add_re, Complex.mul_re, Complex.I_re, Complex.I_im]
  have hbound := riemannZeta_norm_le_re (s := (σ : ℂ) + Complex.I * (t : ℂ)) (by rw [hre]; exact hσ)
  rw [hre] at hbound
  exact hbound.trans (zeta_re_le_two_div_sub_one hσ hσ2)

/-- **Uniform-in-height bound, stated in terms of `Re s`.**

For any complex `s` with `1 < Re s ≤ 2`, `‖ζ s‖ ≤ 2/(Re s - 1)`. -/
theorem norm_zeta_le_of_one_lt_re {s : ℂ} (h1 : 1 < s.re) (h2 : s.re ≤ 2) :
    ‖riemannZeta s‖ ≤ 2 / (s.re - 1) := by
  have hdecomp : s = ((s.re : ℂ) + Complex.I * (s.im : ℂ)) := by
    apply Complex.ext <;> simp [Complex.add_re, Complex.mul_re, Complex.I_re, Complex.I_im]
  have hre : ((s.re : ℂ) + Complex.I * (s.im : ℂ)).re = s.re := by
    simp [Complex.add_re, Complex.mul_re, Complex.I_re, Complex.I_im]
  have := norm_zeta_le_two_div_sub_one (σ := s.re) (t := s.im) h1 h2
  rw [hdecomp, hre]
  exact this

end Zeta
