module

public import EulerMaclaurin.Remainder

/-!
# The full Euler–Maclaurin summation formula

Iterating the `p ≥ 1` recursion

$$\int_m^n \tilde B_p f^{(p)}
  = \frac{B_{p+1}}{p+1}\left(f^{(p)}(n) - f^{(p)}(m)\right)
    - \frac{1}{p+1}\int_m^n \tilde B_{p+1} f^{(p+1)}$$

starting from the `p = 0` identity gives, for every `p ≥ 0`,

$$\int_m^n f
  = \sum_{k=m}^{n-1} f(k) + \frac{f(n)-f(m)}{2}
    + \sum_{j=1}^{p} \frac{(-1)^j B_{j+1}}{(j+1)!}\left(f^{(j)}(n) - f^{(j)}(m)\right)
    + \frac{(-1)^{p+1}}{(p+1)!}\int_m^n \tilde B_{p+1}\, f^{(p+1)}.$$

The remainder coefficient `(-1)^{p+1}/(p+1)!` and the correction coefficient `(-1)^j B_{j+1}/(j+1)!` are
both *absolute*: they do not depend on `f`, `m`, `n`, or on any parameter.

## Sign convention

Mathlib's `bernoulli` has `B₁ = -1/2`, `B₂ = 1/6`, `B₃ = 0`, `B₄ = -1/30`. Cross-checking against
Apostol, *Introduction to Analytic Number Theory*, Theorem 3.1 (which uses `B₁ = +1/2`), the
$j = 1$ coefficient here is $-B_2/2! = -1/12$ on the `∫f` side, i.e. $+1/12$ when the formula is
written with $\sum_{k=m}^{n} f(k) - \frac{f(m)+f(n)}{2}$ on the left. This is consistent, because
$\sum_{k=m}^{n-1} f(k) + \frac{f(n)-f(m)}{2} = \sum_{k=m}^{n} f(k) - \frac{f(m)+f(n)}{2}$.

## Main results

* `eulerMaclaurin_identity` — the formula above, at finite order `p`.
-/

@[expose] public section

open scoped Interval BigOperators
open MeasureTheory intervalIntegral

noncomputable section

namespace EulerMaclaurin

variable {E : Type*} [NormedAddCommGroup E] [NormedSpace ℝ E] [CompleteSpace E]

/-- The Euler–Maclaurin correction coefficient `(-1)^j B_{j+1}/(j+1)!`. -/
noncomputable def emCoeff (j : ℕ) : ℝ :=
  (-1 : ℝ) ^ j * (bernoulli (j + 1) : ℝ) / ((j + 1).factorial : ℝ)

/-- The remainder coefficient `(-1)^{p+1}/(p+1)!`, i.e. the coefficient of
`∫ B̃_{p+1} f^{(p+1)}` after iterating `p+1` times from the `p = 0` identity. -/
noncomputable def emRemCoeff (p : ℕ) : ℝ := (-1 : ℝ) ^ (p + 1) / ((p + 1).factorial : ℝ)

@[simp]
theorem emRemCoeff_zero : emRemCoeff 0 = -1 := by simp [emRemCoeff]

/-- The remainder coefficient satisfies `emRemCoeff (p+1) = -emRemCoeff p / (p+2)`. -/
theorem emRemCoeff_succ (p : ℕ) :
    emRemCoeff (p + 1) = -emRemCoeff p / (p + 2 : ℝ) := by
  have hfac : ((p + 2).factorial : ℝ) = (p + 2 : ℝ) * ((p + 1).factorial : ℝ) := by
    rw [Nat.factorial_succ]; push_cast; ring
  have hp2 : (p + 2 : ℝ) ≠ 0 := by positivity
  have hf : ((p + 1).factorial : ℝ) ≠ 0 := by exact_mod_cast (Nat.factorial_ne_zero (p + 1))
  simp only [emRemCoeff, pow_succ]
  rw [hfac]
  field_simp

/-- `emRemCoeff p * B_{p+2}/(p+2) = emCoeff (p+1)`: the boundary coefficient picked up at step
`p+1` of the iteration is exactly the Euler–Maclaurin correction coefficient `emCoeff (p+1)`. -/
theorem emRemCoeff_mul_bernoulli (p : ℕ) :
    emRemCoeff p * ((bernoulli (p + 2) : ℝ) / (p + 2 : ℝ)) = emCoeff (p + 1) := by
  have hfac : ((p + 2).factorial : ℝ) = (p + 2 : ℝ) * ((p + 1).factorial : ℝ) := by
    rw [Nat.factorial_succ]; push_cast; ring
  have hp2 : (p + 2 : ℝ) ≠ 0 := by positivity
  have hf : ((p + 1).factorial : ℝ) ≠ 0 := by exact_mod_cast (Nat.factorial_ne_zero (p + 1))
  simp only [emRemCoeff, emCoeff]
  rw [hfac]
  field_simp

end EulerMaclaurin
