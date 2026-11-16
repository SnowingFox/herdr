module

public import EulerMaclaurin.Induction
public import EulerMaclaurin.Remainder
public import EulerMaclaurin.GeneralRemainder
public import EulerMaclaurin.SumIntegral

/-!
# Euler–Maclaurin stated with ordinary derivatives

The main identity `eulerMaclaurin_identity` is stated with `iteratedDerivWithin j f s`, i.e.
derivatives relative to the open set `s`. That generality is needed for functions which are only
smooth on `s` (the zeta summand `x ↦ x^{-s}` on `(0, ∞)` is the motivating example), but it is
inconvenient for a consumer whose `f` is smooth on all of `ℝ` and who wants to quote `f^{(j)}` in the
ordinary sense.

This file removes that friction. Since `iteratedDerivWithin j f Set.univ = iteratedDeriv j f`
(Mathlib's `iteratedDerivWithin_univ`), taking `s = univ` turns the identity into

$$\int_m^n f = \sum_{k=m}^{n-1} f(k) + \frac{f(n)-f(m)}{2}
  + \sum_{j=1}^{p} c_j \left(f^{(j)}(n) - f^{(j)}(m)\right)
  + c'_p \int_m^n \tilde B_{p+1}\, f^{(p+1)},$$

where now **every** `f^{(j)}` is the ordinary iterated derivative `iteratedDeriv j f`.

Two simplifications fall out, and they are the reason this form is preferable downstream:

* the hypotheses `IsOpen s` and `hsub : Icc m n ⊆ s` disappear — `s = univ` satisfies both
  trivially, so the only analytic hypothesis left is `ContDiff ℝ (p+2) f`;
* the conclusion mentions no auxiliary set at all.

So the `univ` restatement is strictly *easier to apply* than the general one: it trades three
hypotheses for one and removes a parameter. It is not weaker — `ContDiff ℝ (p+2) f` implies
`ContDiffOn ℝ (p+2) f univ`, and any consumer who is happy to assume global smoothness gets exactly
the same conclusion with ordinary derivatives.

## Main results

* `eulerMaclaurin_identity_univ` — the identity with ordinary derivatives.
* `abs_integral_sub_eulerMaclaurin_le_univ` — the general-order remainder bound.
* `abs_integral_sub_sum_sub_half_le_univ` — the sharp `p = 1` trapezoid bound.
* `abs_sum_Ico_sub_integral_le_univ` — the sum-versus-integral bound.
-/

@[expose] public section

open scoped Interval BigOperators
open MeasureTheory intervalIntegral

noncomputable section

namespace EulerMaclaurin

/-- The bridge used throughout this file: on `univ`, the derivative relative to a set is the
ordinary iterated derivative. Recorded as a named lemma so consumers can find it from this
namespace. -/
theorem iteratedDerivWithin_univ_eq (j : ℕ) (f : ℝ → ℝ) :
    iteratedDerivWithin j f Set.univ = iteratedDeriv j f :=
  iteratedDerivWithin_univ

/-- **Euler–Maclaurin summation with ordinary derivatives.**

For `f : ℝ → ℝ` of class `C^{p+2}` on all of `ℝ`,

`∫_m^n f = Σ_{k∈Ico m n} f(k) + (f(n)-f(m))/2
            + Σ_{j=1}^{p} c_j (f^{(j)}(n) - f^{(j)}(m))
            + c'_p ∫_m^n B̃_{p+1} f^{(p+1)}`

with `c_j = emCoeff j`, `c'_p = emRemCoeff p`, and every `f^{(j)}` the ordinary derivative
`iteratedDeriv j f`. Compare `eulerMaclaurin_identity`, which carries an extra open set `s` and
states the derivatives relative to it. -/
theorem eulerMaclaurin_identity_univ {f : ℝ → ℝ} {m n : ℕ} (hmn : m ≤ n)
    (p : ℕ) (hf : ContDiff ℝ ((p : ℕ) + 2) f) :
    ∫ x in (m : ℝ)..(n : ℝ), f x
      = ∑ k ∈ Finset.Ico m n, f (k : ℝ) + (f (n : ℝ) - f (m : ℝ)) / 2
        + emBoundary p (fun j => iteratedDeriv j f (n : ℝ) - iteratedDeriv j f (m : ℝ))
        + emRemCoeff p * ∫ x in (m : ℝ)..(n : ℝ),
            (periodicBernoulli (p + 1) x : ℝ) • iteratedDeriv (p + 1) f x := by
  have h := eulerMaclaurin_identity (s := Set.univ) isOpen_univ hmn (Set.subset_univ _) p
    (contDiffOn_univ.mpr hf)
  simpa only [iteratedDerivWithin_univ] using h

/-- **General-order Euler–Maclaurin remainder bound with ordinary derivatives.**

For `f` of class `C^{p+2}` on `ℝ` and any `M` bounding `|B_{p+1}|` on `[0,1]`, the error in the
Euler–Maclaurin approximation through order `p` is at most `M/(p+1)! · ∫_m^n |f^{(p+1)}|`, with
`f^{(p+1)}` the ordinary derivative. -/
theorem abs_integral_sub_eulerMaclaurin_le_univ {f : ℝ → ℝ} {m n : ℕ} (hmn : m ≤ n)
    (p : ℕ) (hf : ContDiff ℝ ((p : ℕ) + 2) f)
    {M : ℝ} (hMbound : ∀ y ∈ Set.Icc (0 : ℝ) 1, |bernoulliFun (p + 1) y| ≤ M) :
    |(∫ x in (m : ℝ)..(n : ℝ), f x)
        - (∑ k ∈ Finset.Ico m n, f (k : ℝ)) - (f (n : ℝ) - f (m : ℝ)) / 2
        - emBoundary p (fun j => iteratedDeriv j f (n : ℝ) - iteratedDeriv j f (m : ℝ))|
      ≤ M / ((p + 1).factorial : ℝ) * ∫ x in (m : ℝ)..(n : ℝ),
          |iteratedDeriv (p + 1) f x| := by
  have h := abs_integral_sub_eulerMaclaurin_le (s := Set.univ) isOpen_univ hmn
    (Set.subset_univ _) p (contDiffOn_univ.mpr hf) hMbound
  simpa only [iteratedDerivWithin_univ] using h

/-- **Sharp `p = 1` trapezoid bound with ordinary derivatives.**

For `f` of class `C²` on `ℝ` with derivative `f'`,
`|∫_m^n f − Σ_{k∈Ico m n} f(k) − (f(n)−f(m))/2| ≤ (1/2)∫_m^n |f'|`.
The constant `1/2` is the sharp `max |B̃₁|`. -/
theorem abs_integral_sub_sum_sub_half_le_univ {f f' : ℝ → ℝ} {m n : ℕ} (hmn : m ≤ n)
    (hf : ContDiff ℝ 2 f) (hderiv : ∀ x, HasDerivAt f (f' x) x) :
    |(∫ x in (m : ℝ)..(n : ℝ), f x)
        - (∑ k ∈ Finset.Ico m n, f (k : ℝ)) - (f (n : ℝ) - f (m : ℝ)) / 2|
      ≤ (1 / 2) * ∫ x in (m : ℝ)..(n : ℝ), |f' x| :=
  abs_integral_sub_sum_sub_half_le (s := Set.univ) isOpen_univ hmn (Set.subset_univ _)
    (contDiffOn_univ.mpr hf) (fun x _ => hderiv x)

/-- **Sum-versus-integral bound with ordinary derivatives.**

For `f` of class `C²` on `ℝ` with derivative `f'`,
`|Σ_{k=m}^{n-1} f(k) − ∫_m^n f| ≤ |f(n)−f(m)|/2 + (1/2)∫_m^n |f'|`.
Both terms on the right are explicit in `f`, `m`, `n`, and `1/2` is sharp. -/
theorem abs_sum_Ico_sub_integral_le_univ {f f' : ℝ → ℝ} {m n : ℕ} (hmn : m ≤ n)
    (hf : ContDiff ℝ 2 f) (hderiv : ∀ x, HasDerivAt f (f' x) x) :
    |(∑ k ∈ Finset.Ico m n, f (k : ℝ)) - ∫ x in (m : ℝ)..(n : ℝ), f x|
      ≤ |f (n : ℝ) - f (m : ℝ)| / 2
        + (1 / 2) * ∫ x in (m : ℝ)..(n : ℝ), |f' x| :=
  abs_sum_Ico_sub_integral_le (s := Set.univ) isOpen_univ hmn (Set.subset_univ _)
    (contDiffOn_univ.mpr hf) (fun x _ => hderiv x)

end EulerMaclaurin

/-! ### Checks that the `univ` form is faithful and non-vacuous -/

/-- The bridge, at a point. -/
example (j : ℕ) (f : ℝ → ℝ) (x : ℝ) :
    iteratedDerivWithin j f Set.univ x = iteratedDeriv j f x := by
  rw [iteratedDerivWithin_univ]

/-- `ContDiff` implies the `ContDiffOn … univ` hypothesis of the general form, so the `univ`
restatement loses nothing. -/
example {f : ℝ → ℝ} {p : ℕ} (hf : ContDiff ℝ ((p : ℕ) + 2) f) :
    ContDiffOn ℝ ((p : ℕ) + 2) f Set.univ :=
  contDiffOn_univ.mpr hf

/-- The hypotheses are satisfiable by the intended objects: `x ↦ x²` is `C²`, so
`abs_integral_sub_sum_sub_half_le_univ` is not vacuous. -/
example : ContDiff ℝ 2 (fun x : ℝ => x ^ 2) := by fun_prop
