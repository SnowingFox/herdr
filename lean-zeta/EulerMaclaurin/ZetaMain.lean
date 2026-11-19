module

public import EulerMaclaurin.ZetaSmooth
public import EulerMaclaurin.Remainder

/-!
# The quantitative tail bound for the zeta summand

Euler–Maclaurin applied to the real function `f(x) = x^{-σ}` with `σ = Re s > 0`, followed by the
closed-form evaluation of `∫ |f'|`, gives the tail bound used to continue `ζ`:

$$\left|\sum_{k=m}^{n-1} k^{-\sigma} - \int_m^n x^{-\sigma}dx
    - \frac{m^{-\sigma} + n^{-\sigma}}{2}\right|
  \le \frac{m^{-\sigma} - n^{-\sigma}}{2}.$$

The right-hand side is **uniform in `n`** and tends to `m^{-σ}/2` as `n → ∞`; this is the
quantitative input a zero-free-region or Hardy argument consumes.

## Main results

* `deriv_rpow_neg` — `∂_x x^{-σ} = -σ x^{-σ-1}`.
* `abs_eulerMaclaurin_rpow_le` — the bound above.
-/

@[expose] public section

open scoped Interval BigOperators
open MeasureTheory intervalIntegral Complex

noncomputable section

namespace EulerMaclaurin

/-- `∂_x x^{-σ} = -σ · x^{-σ-1}` for `x > 0`. -/
theorem hasDerivAt_rpow_neg {σ : ℝ} {x : ℝ} (hx : x ≠ 0) :
    HasDerivAt (fun y : ℝ => y ^ (-σ)) (-σ * x ^ (-σ - 1)) x :=
  Real.hasDerivAt_rpow_const (Or.inl hx)

/-- `|∂_x x^{-σ}| = σ x^{-σ-1}` for `x > 0` and `σ ≥ 0`. -/
theorem abs_deriv_rpow_neg {σ : ℝ} (hσ : 0 ≤ σ) {x : ℝ} (hx : 0 < x) :
    |-σ * x ^ (-σ - 1)| = σ * x ^ (-σ - 1) := by
  have hpos : 0 < x ^ (-σ - 1) := Real.rpow_pos_of_pos hx _
  rw [abs_mul, abs_neg, abs_of_pos hpos, abs_of_nonneg hσ]

/-- **Euler–Maclaurin tail bound for `x^{-σ}`.**

For `σ > 0` and `1 ≤ m ≤ n`,
`|Σ_{k∈Ico m n} k^{-σ} − ∫_m^n x^{-σ} − (m^{-σ} − n^{-σ})/2| ≤ (m^{-σ} − n^{-σ})/2`.

The bound improves as `n` grows and is uniform in `n`. -/
theorem abs_eulerMaclaurin_rpow_le {σ : ℝ} (hσ : 0 < σ)
    {m n : ℕ} (hm : 1 ≤ m) (hmn : m ≤ n) :
    |(∑ k ∈ Finset.Ico m n, (k : ℝ) ^ (-σ))
        - (∫ x in (m : ℝ)..(n : ℝ), x ^ (-σ))
        - ((m : ℝ) ^ (-σ) - (n : ℝ) ^ (-σ)) / 2|
      ≤ ((m : ℝ) ^ (-σ) - (n : ℝ) ^ (-σ)) / 2 := by
  have hm0 : (0 : ℝ) < (m : ℝ) := by exact_mod_cast hm
  have hmn' : (m : ℝ) ≤ (n : ℝ) := Nat.cast_le.mpr hmn
  have hsub : Set.Icc (m : ℝ) (n : ℝ) ⊆ Set.Ioi 0 :=
    fun x hx => lt_of_lt_of_le hm0 hx.1
  -- the `p = 1` bound, in the shape we need
  have hmain := abs_integral_sub_sum_sub_half_le (s := Set.Ioi (0:ℝ)) isOpen_Ioi hmn hsub
    (contDiffOn_two_rpow_neg σ) (fun x hx => hasDerivAt_rpow_neg (ne_of_gt hx))
  -- rearrange `hmain` into the target's orientation
  have hmain' : |(∑ k ∈ Finset.Ico m n, (k : ℝ) ^ (-σ))
        - (∫ x in (m : ℝ)..(n : ℝ), x ^ (-σ))
        - ((m : ℝ) ^ (-σ) - (n : ℝ) ^ (-σ)) / 2|
      ≤ 1 / 2 * ∫ x in (m : ℝ)..(n : ℝ), |-σ * x ^ (-σ - 1)| := by
    have hset : (∑ k ∈ Finset.Ico m n, (k : ℝ) ^ (-σ))
          - (∫ x in (m : ℝ)..(n : ℝ), x ^ (-σ))
          - ((m : ℝ) ^ (-σ) - (n : ℝ) ^ (-σ)) / 2
        = -(((∫ x in (m : ℝ)..(n : ℝ), x ^ (-σ))
            - (∑ k ∈ Finset.Ico m n, (k : ℝ) ^ (-σ))
            - ((n : ℝ) ^ (-σ) - (m : ℝ) ^ (-σ)) / 2)) := by ring
    rw [hset, abs_neg]
    exact hmain
  have hderiv_eq : ∀ x ∈ Set.Icc (m : ℝ) (n : ℝ), |-σ * x ^ (-σ - 1)| = σ * x ^ (-σ - 1) :=
    fun x hx => abs_deriv_rpow_neg hσ.le (lt_of_lt_of_le hm0 hx.1)
  have hint_eq : ∫ x in (m : ℝ)..(n : ℝ), |-σ * x ^ (-σ - 1)|
      = σ * ∫ x in (m : ℝ)..(n : ℝ), x ^ (-σ - 1) := by
    rw [← intervalIntegral.integral_const_mul]
    apply intervalIntegral.integral_congr
    intro x hx
    rw [Set.uIcc_of_le hmn'] at hx
    exact hderiv_eq x hx
  have hclosed : ∫ x in (m : ℝ)..(n : ℝ), x ^ (-σ - 1)
      = ((m : ℝ) ^ (-σ) - (n : ℝ) ^ (-σ)) / σ :=
    integral_rpow_neg_sub_one hσ hm0 hmn'
  have hR : (1 / 2) * ∫ x in (m : ℝ)..(n : ℝ), |-σ * x ^ (-σ - 1)|
      = ((m : ℝ) ^ (-σ) - (n : ℝ) ^ (-σ)) / 2 := by
    rw [hint_eq, hclosed]
    have hσne : σ ≠ 0 := ne_of_gt hσ
    field_simp
  rw [hR] at hmain'
  exact hmain' 

/-- **Uniform-in-`n` form.** The bound `(m^{-σ} - n^{-σ})/2` is at most `m^{-σ}/2` independently of
`n`, since `n^{-σ} ≥ 0`. This is the shape consumed as a tail estimate: the error does not grow with
`n`. -/
theorem abs_eulerMaclaurin_rpow_le_uniform {σ : ℝ} (hσ : 0 < σ)
    {m n : ℕ} (hm : 1 ≤ m) (hmn : m ≤ n) :
    |(∑ k ∈ Finset.Ico m n, (k : ℝ) ^ (-σ))
        - (∫ x in (m : ℝ)..(n : ℝ), x ^ (-σ))
        - ((m : ℝ) ^ (-σ) - (n : ℝ) ^ (-σ)) / 2|
      ≤ (m : ℝ) ^ (-σ) / 2 := by
  refine (abs_eulerMaclaurin_rpow_le hσ hm hmn).trans ?_
  have hn0 : (0 : ℝ) ≤ (n : ℝ) := Nat.cast_nonneg n
  have hp : 0 ≤ (n : ℝ) ^ (-σ) := Real.rpow_nonneg hn0 _
  linarith

end EulerMaclaurin
