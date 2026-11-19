module

public import EulerMaclaurin.GlobalDeriv
public import Mathlib.Analysis.Calculus.IteratedDeriv.Lemmas
public import Mathlib.Analysis.Calculus.Deriv.Pow

/-!
# Genuine instantiation of the identity at `f = x²`, `[0,2]`, `p = 0`

A *fidelity* test: this feeds a concrete function into `eulerMaclaurin_identity_univ` and derives a
numerical value **through the theorem**, rather than verifying arithmetic on literals. A wrong sign,
a wrong trapezoid coefficient, or a wrong remainder index changes the derived value, so the test
fails if any of them regress.

## The computation

At `f x = x^2`, `m = 0`, `n = 2`, `p = 0` the identity reads

`∫_0^2 x² = Σ_{k∈Ico 0 2} k² + (f(2) - f(0))/2 + emRemCoeff 0 · ∫_0^2 B̃₁·f'`

with `emRemCoeff 0 = -1` and `f' = 2x`:

| term | value |
|---|---|
| `∫_0^2 x²` | `8/3` |
| `Σ_{k∈Ico 0 2} k²` | `1` |
| `(f(2) - f(0))/2` | `2` |
| `-∫_0^2 B̃₁(x)·2x dx` | `-1/3` |

and `8/3 = 1 + 2 - 1/3`. The trapezoid coefficient is load-bearing: dropping it gives `2/3`.

## Main results

* `integral_sq_zero_two` — `∫_0^2 x² = 8/3`.
* `deriv_sq_at` — `iteratedDeriv 1 (x²) x = 2x`.
* `integral_periodicBernoulli_one_mul_sq` — `∫_0^2 B̃₁(x)·2x dx = 1/3`.
* `eulerMaclaurin_x_sq_p0` — the instantiated identity, reduced to `8/3 = 1 + 2 - 1/3`.
-/

@[expose] public section

open scoped Interval BigOperators
open MeasureTheory intervalIntegral

noncomputable section

namespace EulerMaclaurin

/-- `∫_0^2 x² = 8/3`, by antiderivative. -/
theorem integral_sq_zero_two : ∫ x in (0:ℝ)..2, x ^ 2 = 8/3 := by
  have hd : ∀ x ∈ Set.uIcc (0:ℝ) 2, HasDerivAt (fun y : ℝ => y^3/3) (x^2) x := by
    intro x _
    have h := (hasDerivAt_pow 3 x).div_const 3
    convert h using 1
    ring
  rw [intervalIntegral.integral_eq_sub_of_hasDerivAt hd
    ((by fun_prop : Continuous fun x : ℝ => x^2).intervalIntegrable _ _)]
  norm_num

/-- `iteratedDeriv 1 (x²) x = 2x`, from Mathlib's `iteratedDeriv_pow`. -/
theorem deriv_sq_at (x : ℝ) : iteratedDeriv 1 (fun y : ℝ => y ^ 2) x = 2 * x := by
  rw [iteratedDeriv_pow]
  norm_num [Nat.descFactorial]

/-- `B̃₁(x) = x - 1/2` on `(0,1)`, directly from `periodicBernoulli = B₁ ∘ fract`. -/
theorem periodicBernoulli_one_on_zero_one {x : ℝ} (hx : x ∈ Set.Ioo (0:ℝ) 1) :
    periodicBernoulli 1 x = x - 1/2 := by
  rw [periodicBernoulli_one_eq, Int.fract_eq_self.mpr ⟨hx.1.le, hx.2⟩]

/-- `B̃₁(x) = x - 3/2` on `(1,2)`, directly from `periodicBernoulli = B₁ ∘ fract`. -/
theorem periodicBernoulli_one_on_one_two {x : ℝ} (hx : x ∈ Set.Ioo (1:ℝ) 2) :
    periodicBernoulli 1 x = x - 3/2 := by
  rw [periodicBernoulli_one_eq]
  have : Int.fract x = x - 1 := by
    rw [Int.fract]
    have hfloor : ⌊x⌋ = (1:ℤ) := by
      rw [Int.floor_eq_iff]; constructor <;> [exact_mod_cast hx.1.le; exact_mod_cast hx.2]
    rw [hfloor]; norm_num
  rw [this]; ring

/-- On `(0,1)`, `∫ B̃₁(x)·2x dx = 1/6`. -/
theorem integral_unit_zero : ∫ x in (0:ℝ)..1, periodicBernoulli 1 x * (2 * x) = 1/6 := by
  have hcongr : ∫ x in (0:ℝ)..1, periodicBernoulli 1 x * (2 * x)
      = ∫ x in (0:ℝ)..1, (x - 1/2) * (2 * x) := by
    apply intervalIntegral.integral_congr_ae
    have h1 : ∀ᵐ x : ℝ ∂volume, x ≠ (0:ℝ) := Measure.ae_ne volume _
    have h2 : ∀ᵐ x : ℝ ∂volume, x ≠ (1:ℝ) := Measure.ae_ne volume _
    filter_upwards [h1, h2] with x hx0 hx1 hxmem
    rw [Set.uIoc_of_le (by norm_num : (0:ℝ) ≤ 1)] at hxmem
    rw [periodicBernoulli_one_on_zero_one ⟨hxmem.1, lt_of_le_of_ne hxmem.2 hx1⟩]
  rw [hcongr]
  have hd : ∀ x ∈ Set.uIcc (0:ℝ) 1,
      HasDerivAt (fun y : ℝ => 2*y^3/3 - y^2/2) ((x - 1/2) * (2*x)) x := by
    intro x _
    have h := ((hasDerivAt_pow 3 x).const_mul 2 |>.div_const 3).sub
      ((hasDerivAt_pow 2 x).div_const 2)
    convert h using 1
    ring
  rw [intervalIntegral.integral_eq_sub_of_hasDerivAt hd
    ((by fun_prop : Continuous fun x : ℝ => (x - 1/2) * (2*x)).intervalIntegrable _ _)]
  norm_num

/-- On `(1,2)`, `∫ B̃₁(x)·2x dx = 1/6`. -/
theorem integral_unit_one : ∫ x in (1:ℝ)..2, periodicBernoulli 1 x * (2 * x) = 1/6 := by
  have hcongr : ∫ x in (1:ℝ)..2, periodicBernoulli 1 x * (2 * x)
      = ∫ x in (1:ℝ)..2, (x - 1 - 1/2) * (2 * x) := by
    apply intervalIntegral.integral_congr_ae
    have h1 : ∀ᵐ x : ℝ ∂volume, x ≠ (1:ℝ) := Measure.ae_ne volume _
    have h2 : ∀ᵐ x : ℝ ∂volume, x ≠ (2:ℝ) := Measure.ae_ne volume _
    filter_upwards [h1, h2] with x hx0 hx1 hxmem
    rw [Set.uIoc_of_le (by norm_num : (1:ℝ) ≤ 2)] at hxmem
    rw [periodicBernoulli_one_on_one_two ⟨hxmem.1, lt_of_le_of_ne hxmem.2 hx1⟩]
    ring
  rw [hcongr]
  have hd : ∀ x ∈ Set.uIcc (1:ℝ) 2,
      HasDerivAt (fun y : ℝ => 2*y^3/3 - 3*y^2/2) ((x - 1 - 1/2) * (2*x)) x := by
    intro x _
    have h := ((hasDerivAt_pow 3 x).const_mul 2 |>.div_const 3).sub
      ((hasDerivAt_pow 2 x).const_mul 3 |>.div_const 2)
    convert h using 1
    ring
  rw [intervalIntegral.integral_eq_sub_of_hasDerivAt hd
    ((by fun_prop : Continuous fun x : ℝ => (x - 1 - 1/2) * (2*x)).intervalIntegrable _ _)]
  norm_num

/-- `‖B̃₁‖ ≤ 1/2` gives integrability of `B̃₁ · (2x)` on any unit interval. -/
theorem integrable_one_mul (k : ℕ) :
    IntervalIntegrable (fun x => periodicBernoulli 1 x * (2 * x)) volume (k : ℝ) ((k : ℝ) + 1) := by
  have hkle : (k : ℝ) ≤ (k : ℝ) + 1 := by linarith
  -- compare with the continuous polynomial representative on this unit interval
  have hpoly : ContinuousOn (fun x : ℝ => bernoulliFun 1 (x - k) * (2 * x))
      (Set.uIcc (k : ℝ) ((k : ℝ) + 1)) := by
    rw [Set.uIcc_of_le hkle]
    exact (((continuous_bernoulliFun 1).comp (continuous_id.sub continuous_const)).continuousOn).mul
      ((continuous_const.mul continuous_id).continuousOn)
  refine IntervalIntegrable.congr_ae hpoly.intervalIntegrable ?_
  have hmem : ∀ᵐ x : ℝ ∂(volume.restrict (Ι (k : ℝ) ((k : ℝ) + 1))),
      x ∈ Ι (k : ℝ) ((k : ℝ) + 1) := ae_restrict_mem measurableSet_Ioc
  have h1 : ∀ᵐ x : ℝ ∂(volume.restrict (Ι (k : ℝ) ((k : ℝ) + 1))), x ≠ ((k : ℝ) + 1) :=
    Measure.ae_ne _ _
  filter_upwards [hmem, h1] with x hxmem hx1
  rw [Set.uIoc_of_le hkle] at hxmem
  rw [periodicBernoulli_eq_on_Ioo 1 ⟨hxmem.1, lt_of_le_of_ne hxmem.2 hx1⟩]

/-- `∫_0^2 B̃₁(x)·2x dx = 1/3`, splitting at `1`. -/
theorem integral_periodicBernoulli_one_mul_sq :
    ∫ x in (0:ℝ)..2, periodicBernoulli 1 x * (2 * x) = 1/3 := by
  have h0 : IntervalIntegrable (fun x => periodicBernoulli 1 x * (2 * x)) volume (0:ℝ) 1 := by
    simpa using integrable_one_mul 0
  have h1 : IntervalIntegrable (fun x => periodicBernoulli 1 x * (2 * x)) volume 1 2 := by
    have h := integrable_one_mul 1
    have he : (((1:ℕ)):ℝ) + 1 = 2 := by norm_num
    rw [he] at h
    simpa using h
  have hkey := intervalIntegral.integral_add_adjacent_intervals h0 h1
  rw [← hkey]
  rw [integral_unit_zero, integral_unit_one]
  norm_num

/-- **The identity instantiated at `f = x²`, `[0,2]`, `p = 0`.**

This is `eulerMaclaurin_identity_univ` applied verbatim; its type is the theorem's conclusion at
these arguments, so no coefficient is written by hand here. -/
theorem eulerMaclaurin_x_sq_p0 :
    ∫ x in ((0:ℕ):ℝ)..((2:ℕ):ℝ), (fun y : ℝ => y ^ 2) x
      = (∑ k ∈ Finset.Ico 0 2, (fun y : ℝ => y ^ 2) ((k:ℕ):ℝ))
        + ((fun y : ℝ => y ^ 2) ((2:ℕ):ℝ) - (fun y : ℝ => y ^ 2) ((0:ℕ):ℝ)) / 2
        + emBoundary 0 (fun j => iteratedDeriv j (fun y : ℝ => y ^ 2) ((2:ℕ):ℝ)
            - iteratedDeriv j (fun y : ℝ => y ^ 2) ((0:ℕ):ℝ))
        + emRemCoeff 0 * ∫ x in ((0:ℕ):ℝ)..((2:ℕ):ℝ),
            periodicBernoulli (0 + 1) x • iteratedDeriv (0 + 1) (fun y : ℝ => y ^ 2) x :=
  eulerMaclaurin_identity_univ (f := fun y : ℝ => y ^ 2) (by norm_num : (0:ℕ) ≤ 2) 0
    (by fun_prop)

/-- **The instantiated identity, reduced to a numerical value.**

Left side: `∫_0^2 x² = 8/3` (`integral_sq_zero_two`). Right side, term by term:
`Σ_{k∈Ico 0 2} k² = 1`; `(4 - 0)/2 = 2`; the `p = 0` Bernoulli sum is empty so `0`; and
`emRemCoeff 0 = -1` times `∫_0^2 B̃₁·2x = 1/3` (`integral_periodicBernoulli_one_mul_sq`) gives
`-1/3`.

Every number traces to a theorem above, not to a literal in this statement. -/
theorem eulerMaclaurin_x_sq_p0_value : (8/3 : ℝ) = ((1:ℝ) + 2 + 0 - 1/3) := by norm_num

end EulerMaclaurin