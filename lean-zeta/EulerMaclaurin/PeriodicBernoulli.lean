module

public import Mathlib.NumberTheory.ZetaValues
public import Mathlib.MeasureTheory.Integral.IntervalIntegral.IntegrationByParts
public import Mathlib.Analysis.Calculus.IteratedDeriv.Lemmas

/-!
# Periodic Bernoulli functions

The `n`-th periodic Bernoulli function is
$$\tilde B_n(x) = B_n(\{x\}),$$
where `B_n` is the `n`-th Bernoulli polynomial (`bernoulliFun`) and `\{x\}` is the fractional part.

These are the natural carriers of the Euler–Maclaurin remainder: on each unit interval `(k, k+1)`,
`\tilde B_n` agrees with the polynomial `B_n(· - k)`, and `\tilde B_n' = n \tilde B_{n-1}` there.

## Main results

* `periodicBernoulli` — the definition.
* `periodicBernoulli_add_one` — 1-periodicity.
* `periodicBernoulli_eq_bernoulliFun_sub_floor` — `\tilde B_n x = B_n (x - ⌊x⌋)`.
* `periodicBernoulli_eq_on_Ioo` — on `(k, k+1)` it is the polynomial `B_n(· - k)`.
* `hasDerivAt_bernoulliFun_sub` — the derivative of `x ↦ B_n (x - k)`.

## Implementation notes

For `n = 1` the periodic Bernoulli function has a jump at the integers, so we deliberately never
state a derivative formula for `\tilde B_1` at integers. Every consumer in this development
integrates over unit intervals, where the jump point is a single point and hence null; we therefore
state agreement with the polynomial on the *open* interval `(k, k+1)` and lift to integrals via
`integral_congr_ae`.
-/

@[expose] public section

open scoped Interval BigOperators
open MeasureTheory intervalIntegral

noncomputable section

namespace EulerMaclaurin

/-- The `n`-th periodic Bernoulli function `\tilde B_n(x) = B_n({x})`. -/
noncomputable def periodicBernoulli (n : ℕ) (x : ℝ) : ℝ := bernoulliFun n (Int.fract x)

@[simp]
theorem periodicBernoulli_zero (x : ℝ) : periodicBernoulli 0 x = 1 := by
  simp [periodicBernoulli]

theorem periodicBernoulli_eq_bernoulliFun_sub_floor (n : ℕ) (x : ℝ) :
    periodicBernoulli n x = bernoulliFun n (x - ⌊x⌋) := by
  simp [periodicBernoulli, Int.self_sub_floor]

/-- The periodic Bernoulli functions are 1-periodic. -/
theorem periodicBernoulli_add_one (n : ℕ) (x : ℝ) :
    periodicBernoulli n (x + 1) = periodicBernoulli n x := by
  simp [periodicBernoulli, Int.fract_add_one]

theorem periodicBernoulli_add_natCast (n : ℕ) (x : ℝ) (m : ℕ) :
    periodicBernoulli n (x + m) = periodicBernoulli n x := by
  simp [periodicBernoulli, Int.fract_add_natCast]

theorem periodicBernoulli_add_intCast (n : ℕ) (x : ℝ) (m : ℤ) :
    periodicBernoulli n (x + m) = periodicBernoulli n x := by
  simp [periodicBernoulli, Int.fract_add_intCast]

/-- On an open unit interval, the periodic Bernoulli function is the Bernoulli polynomial
translated to that interval. -/
theorem periodicBernoulli_eq_on_Ioo (n : ℕ) {k : ℕ} {x : ℝ} (hx : x ∈ Set.Ioo (k : ℝ) ((k : ℝ) + 1)) :
    periodicBernoulli n x = bernoulliFun n (x - k) := by
  have hfloor : ⌊x⌋ = (k : ℤ) := by
    rw [Int.floor_eq_iff]
    constructor
    · exact_mod_cast hx.1.le
    · exact_mod_cast hx.2
  simp only [periodicBernoulli_eq_bernoulliFun_sub_floor, hfloor, Int.cast_natCast]

/-- A uniform bound for the periodic Bernoulli function on `[0,1]` extends to a bound everywhere. -/
theorem abs_periodicBernoulli_le {n : ℕ} {M : ℝ}
    (hM : ∀ y ∈ Set.Icc (0 : ℝ) 1, |bernoulliFun n y| ≤ M) (x : ℝ) :
    |periodicBernoulli n x| ≤ M := by
  rw [periodicBernoulli_eq_bernoulliFun_sub_floor]
  exact hM _ ⟨Int.fract_nonneg x, (Int.fract_lt_one x).le⟩

/-- The derivative of `x ↦ B_n (x - k)`. -/
theorem hasDerivAt_bernoulliFun_sub (n : ℕ) (k : ℕ) (x : ℝ) :
    HasDerivAt (fun y : ℝ => bernoulliFun n (y - k))
      ((n : ℝ) * bernoulliFun (n - 1) (x - k)) x := by
  have h := (hasDerivAt_bernoulliFun n (x - k)).comp x ((hasDerivAt_id x).sub_const (k : ℝ))
  simpa [Function.comp_def] using h

@[simp]
theorem bernoulliFun_one_zero : bernoulliFun 1 0 = -(1 / 2) := by simp

@[simp]
theorem bernoulliFun_one_one : bernoulliFun 1 1 = 1 / 2 := by simp; norm_num

end EulerMaclaurin
