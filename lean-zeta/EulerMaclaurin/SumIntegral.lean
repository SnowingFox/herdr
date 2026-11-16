module

public import EulerMaclaurin.GeneralRemainder

/-!
# The requested shape: `|∑ f(k) − ∫ f|` with an explicit bound

Downstream consumers usually want the *sum-versus-integral* difference directly, without the
trapezoid and Bernoulli corrections. That follows immediately from the `p = 1` trapezoid estimate by
absorbing the single trapezoid term with the triangle inequality.

## Main results

* `abs_sum_Ico_sub_integral_le` — `|∑_{k=m}^{n-1} f(k) − ∫_m^n f| ≤ |f(n)-f(m)|/2 + (1/2)∫|f'|`.
-/

@[expose] public section

open scoped Interval BigOperators
open MeasureTheory intervalIntegral

noncomputable section

namespace EulerMaclaurin

/-- **Sum-versus-integral bound**, in the exact shape requested.

For `f : ℝ → ℝ` of class `C²` on an open set containing `[m,n]`,

$$\left|\sum_{k=m}^{n-1} f(k) - \int_m^n f\right|
  \le \frac{|f(n)-f(m)|}{2} + \frac{1}{2}\int_m^n |f'| .$$

Every ingredient on the right is explicit in `f`, `m`, `n`, and the constant `1/2` is the sharp
`max|B̃_1|`. -/
theorem abs_sum_Ico_sub_integral_le {f f' : ℝ → ℝ} {s : Set ℝ} (hs : IsOpen s)
    {m n : ℕ} (hmn : m ≤ n)
    (hsub : Set.Icc (m : ℝ) (n : ℝ) ⊆ s)
    (hf : ContDiffOn ℝ 2 f s)
    (hderiv : ∀ x ∈ s, HasDerivAt f (f' x) x) :
    |(∑ k ∈ Finset.Ico m n, f (k : ℝ)) - ∫ x in (m : ℝ)..(n : ℝ), f x|
      ≤ |f (n : ℝ) - f (m : ℝ)| / 2
        + (1 / 2) * ∫ x in (m : ℝ)..(n : ℝ), |f' x| := by
  have h1 := abs_integral_sub_sum_sub_half_le hs hmn hsub hf hderiv
  set I : ℝ := ∫ x in (m : ℝ)..(n : ℝ), f x with hI
  set S : ℝ := ∑ k ∈ Finset.Ico m n, f (k : ℝ) with hS
  set D : ℝ := (f (n : ℝ) - f (m : ℝ)) / 2 with hD
  set R : ℝ := (1 / 2) * ∫ x in (m : ℝ)..(n : ℝ), |f' x| with hR
  -- `h1 : |I - S - D| ≤ R`
  have h1' : |I - S - D| ≤ R := h1
  -- `S - I = -(I - S - D) - D`
  have hdecomp : S - I = -((I - S - D) + D) := by ring
  rw [hdecomp, abs_neg]
  have htri : |(I - S - D) + D| ≤ |I - S - D| + |D| := abs_add_le _ _
  have hD' : |D| = |f (n : ℝ) - f (m : ℝ)| / 2 := by
    rw [hD, abs_div]; norm_num
  calc |(I - S - D) + D| ≤ |I - S - D| + |D| := htri
    _ ≤ R + |f (n : ℝ) - f (m : ℝ)| / 2 := by
        rw [hD']
        linarith
    _ = |f (n : ℝ) - f (m : ℝ)| / 2 + (1 / 2) * ∫ x in (m : ℝ)..(n : ℝ), |f' x| := by
        rw [hR]; ring

end EulerMaclaurin
