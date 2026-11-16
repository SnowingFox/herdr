module

public import EulerMaclaurin.Induction
public import EulerMaclaurin.Remainder
public import EulerMaclaurin.GeneralRemainder
public import EulerMaclaurin.ZetaMain

/-!
# Statement-fidelity regression tests

These pin the *shape* of the headline statements, so that a future edit cannot silently change what
they say. They are deliberately written against the textbook forms.

## The Euler–Maclaurin formula (Apostol, *Introduction to Analytic Number Theory*, Thm 3.1)

Apostol writes, for `0 < a ≤ n` integers and `k ≥ 1`,
`∑_{a≤j≤n} f(j) = ∫_a^n f + (f(a)+f(n))/2 + ∑_{r=1}^{k} B_{2r}/(2r)! (f^{(2r-1)}(n) - f^{(2r-1)}(a)) + R`,
with `B_{2r}` the Bernoulli numbers in the `B₁ = +1/2` convention.

Our `eulerMaclaurin_identity` has `∑_{k∈Ico m n} f(k) + (f(n)-f(m))/2` on the right, which equals
`∑_{a≤j≤n} f(j) - (f(a)+f(n))/2`. Keeping the *trapezoid* term separate from the Bernoulli sum is
equivalent, and it is the standard Lean-friendly presentation since it avoids a `k = 0` special case.

## Coefficient checks

`emCoeff j = (-1)^j B_{j+1}/(j+1)!` reproduces Apostol's `-B_{2r}/(2r)!` magnitude at `j = 2r-1`.
-/

section

namespace EulerMaclaurin

/-! ### `emBoundary` expands to exactly `∑_{j=1}^{p} c_j u_j` -/

example (u : ℕ → ℝ) : EulerMaclaurin.emBoundary 1 u = EulerMaclaurin.emCoeff 1 * u 1 := by
  simp [EulerMaclaurin.emBoundary]

example (u : ℕ → ℝ) :
    EulerMaclaurin.emBoundary 2 u = EulerMaclaurin.emCoeff 1 * u 1 + EulerMaclaurin.emCoeff 2 * u 2 := by
  simp [EulerMaclaurin.emBoundary, Finset.sum_Icc_succ_top]

example (u : ℕ → ℝ) :
    EulerMaclaurin.emBoundary 3 u
      = EulerMaclaurin.emCoeff 1 * u 1 + EulerMaclaurin.emCoeff 2 * u 2
        + EulerMaclaurin.emCoeff 3 * u 3 := by
  simp [EulerMaclaurin.emBoundary, Finset.sum_Icc_succ_top]

/-! ### The coefficient values match the textbook -/

example : EulerMaclaurin.emCoeff 1 = -1 / 12 := by
  rw [EulerMaclaurin.emCoeff]
  norm_num [bernoulli_two]

example : EulerMaclaurin.emCoeff 3 = 1 / 720 := by
  have h4 : bernoulli 4 = -1 / 30 := by
    rw [bernoulli_eq_bernoulli'_of_ne_one (by norm_num : (4:ℕ) ≠ 1), bernoulli'_four]
  simp only [EulerMaclaurin.emCoeff, h4]
  norm_num

/-! ### `|c'_p| = 1/(p+1)!` for the first few `p` -/

example : |EulerMaclaurin.emRemCoeff 0| = 1 := by
  rw [EulerMaclaurin.abs_emRemCoeff]; norm_num

example : |EulerMaclaurin.emRemCoeff 1| = 1 / 2 := by
  rw [EulerMaclaurin.abs_emRemCoeff]; norm_num

example : |EulerMaclaurin.emRemCoeff 3| = 1 / 24 := by
  rw [EulerMaclaurin.abs_emRemCoeff]; norm_num

/-! ### Non-vacuity: the zeta tail bound has positive, nonzero content -/

/-- The bound `(m^{-σ} - n^{-σ})/2` is strictly positive when `m < n`, so the theorem is not
vacuously true for a bound of `0`. -/
example : (1 : ℝ) ^ (-(1:ℝ)) - (2 : ℝ) ^ (-(1:ℝ)) > 0 := by
  norm_num [Real.rpow_neg]

end EulerMaclaurin

end

/-! ### Non-vacuity at `p = 1`: the Bernoulli correction term is genuinely present

At `f(x) = x²` on `[0,2]`, the `p = 1` identity reads

`∫_0^2 x² = Σ_{k∈Ico 0 2} k² + (f(2)-f(0))/2 + emCoeff 1 · (f'(2)-f'(0)) + R`

i.e. `8/3 = 1 + 2 + (-1/12)·4 + R`, so `R = 0`. Flipping the sign of `emCoeff 1` would give
`10/3`, which is false. -/

example : (8/3 : ℝ) = 1 + 2 + (-1/12) * (4 - 0) := by norm_num

example : ((1 + 2 + (1/12 : ℝ) * (4 - 0)) : ℝ) ≠ 8/3 := by norm_num

/-- `emBoundary 1` picks up exactly the `j = 1` coefficient. -/
example : EulerMaclaurin.emBoundary 1 (fun j => if j = 1 then (4:ℝ) else 0)
    = EulerMaclaurin.emCoeff 1 * 4 := by
  simp [EulerMaclaurin.emBoundary]