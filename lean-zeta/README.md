# Zeta: zero-free regions for the Riemann zeta function in Lean 4

A standalone Lake project depending on Mathlib, formalising the classical
de la Vallée Poussin 3-4-1 mechanism for the Riemann zeta function and the
zero-free region it supports.

## Toolchain

- Lean `leanprover/lean4:v4.36.0-rc2`
- Mathlib commit `c1ab78921dd592c4e343e6eb0e6f798910726f62`

```bash
lake exe cache get   # Mathlib build cache; essential
lake build
lake env lean Zeta/Axioms.lean
```

## What is proved

Everything below is `sorry`-free, `admit`-free, uses no new axioms and no
`implemented_by`. `Zeta/Axioms.lean` verifies that every main theorem depends on
exactly `[propext, Classical.choice, Quot.sound]`.

### `Zeta.ThreeFourOne`

| Theorem | Statement |
| --- | --- |
| `three_add_four_cos_add_cos_two` | `0 ≤ 3 + 4 cos θ + cos 2θ` |
| `riemannZeta_norm_product_ge_one` | `x > 0 → ‖ζ(1+x)³ · ζ(1+x+iy)⁴ · ζ(1+x+2iy)‖ ≥ 1` |
| `riemannZeta_norm_le_re` | `1 < Re s → ‖ζ s‖ ≤ Re ζ(Re s)` |
| `riemannZeta_inv_norm_ge_inv_re` | `1 < Re s → 1/Re ζ(Re s) ≤ ‖1/ζ s‖` |
| `riemannZeta_inv_pow_le` | `σ > 1 → ‖1/ζ(σ+it)‖⁴ ≤ Re ζ(σ)³ · ‖ζ(σ+2it)‖` |

`riemannZeta_norm_product_ge_one` is the 3-4-1 inequality for `ζ`, obtained by
specialising Mathlib's `DirichletCharacter.norm_LSeries_product_ge_one` to the
principal character of level 1. `riemannZeta_norm_le_re` and its reciprocal form
are proved from the Dirichlet series on `Re s > 1`.

### `Zeta.ZeroFree`

| Theorem | Statement |
| --- | --- |
| `isCompact_strip` | `{s | 1/2 ≤ Re s ≤ 1 ∧ \|Im s\| ≤ H}` is compact |
| `exists_zero_free_height_local` | `∀ H, ∃ c > 0, ∀ s, \|Im s\| ≤ H → 1 - c/log(\|Im s\|+2) < Re s → ζ s ≠ 0` |
| `exists_zero_free_strip_height_local` | `∀ H, ∃ δ > 0, ∀ s, \|Im s\| ≤ H → 1 - δ < Re s → ζ s ≠ 0` |

These are genuine zero-free regions that cross the line `Re s = 1`, obtained from
finiteness of the zeros in a compact set plus nonvanishing on `Re s ≥ 1`.

## `Zeta.StripBoundFalse` — Target 1 as literally stated is **false**

The assignment's Target 1 was

```lean
∃ C, ∀ s : ℂ, 1/2 ≤ s.re → s.re ≤ 1 → ‖riemannZeta s‖ ≤ C * Real.log (|s.im| + 2)
```

**This is false, and the negation is proved** (`not_strip_bound_at_pole`). The region
`1/2 ≤ Re s ≤ 1` contains the pole `s = 1`; there `Im s = 0`, so the claimed bound reads
`‖ζ 1‖ ≤ C log 2`, while along the real axis `‖ζ σ‖ ~ 1/(1-σ) → ∞` as `σ → 1⁻`
(`tendsto_norm_zeta_at_one`, from `riemannZeta_residue_one`). No `C` can work.

The minimal honest repair is to exclude the pole. Every textbook strip bound is stated on
`1/2 ≤ Re s ≤ 1` with `s ≠ 1`, equivalently on the open strip `s.re < 1`; that is the form any
future `critical_strip_growth` must take. This file exists so the false statement cannot be
silently re-introduced.

## `Zeta.PoleBound` — the pole bound (Target 2)

| Theorem | Statement |
| --- | --- |
| `antitoneOn_rpow_neg` | `σ > 0 → AntitoneOn (x ↦ x^{-σ}) [1,∞)` |
| `tsum_tail_le_integral` | `σ > 1 → ∑_{n≥0} (n+2)^{-σ} ≤ 1/(σ-1)` |
| `zeta_re_eq_tsum` | `σ > 1 → (ζ σ).re = ∑' n, (n+1)^{-σ}` |
| `zeta_re_le_inv_sub_one_add_one` | `σ > 1 → (ζ σ).re ≤ 1 + 1/(σ-1)` |
| `zeta_re_le_two_div_sub_one` | `1 < σ ≤ 2 → (ζ σ).re ≤ 2/(σ-1)` |
| `re_zeta_cube_le` | `1 < σ ≤ 2 → (ζ σ).re³ ≤ 8/(σ-1)³` |

The engine is `AntitoneOn.tsum_comp_add_le_integral` (Mathlib's integral test) plus
`integral_Ioi_rpow_of_lt`, applied to the tail of the Dirichlet series. The constant `2` is an
artefact of the integral test and is **not** claimed optimal: the residue at `1` is `1`, so no
constant below `1` can work as `σ → 1⁺`. The 3-4-1 region depends on the *rate* `1/(σ-1)`, not on
the constant.

## Routing the strip bound: the functional equation, and why it does not close here

The question that decides Target 1 is whether `‖ζ s‖ ≪ log(|Im s|+2)` on the strip is reached
through (a) the functional equation, bounding `ζ` in the strip from `ζ` on the other side, or
(b) the Dirichlet series plus analytic continuation.

**The honest answer: (a) is the correct route, and it needs machinery Mathlib does not have.**
Both routes fail at this commit, for different and independently verifiable reasons.

**Route (b) is blocked outright, and no amount of Euler–Maclaurin fixes it.** The engine's
`norm_sum_Ico_cpow_le_of_lt_one` bounds a *Dirichlet partial sum*
`‖Σ_{k∈Ico m n} k^{-s}‖` by `n^{1-σ}/(1-σ) + m^{-σ}`, uniform in `n` only when `σ > 1`. On
`0 < σ < 1` the partial sums grow like `n^{1-σ}`, so the bound carries `n` explicitly — and the
sum does not converge. To turn that into a statement about `ζ` you need
`ζ(s) = Σ_{k<n} k^{-s} + (correction)`, i.e. an identity relating `riemannZeta` to a *finite* sum
plus a tail. **Mathlib has no such identity.** `zeta_eq_tsum_one_div_nat_add_one_cpow` requires
`1 < re s`, and the only other descriptions of `ζ` are `hurwitzZetaEven` /
`completedRiemannZeta₀`, defined through Mellin transforms, with no finite-sum decomposition. So
route (b) would require deriving the Euler–Maclaurin continuation into the strip from scratch —
which is what the engine explicitly says it does not do.

The handover's warning is exactly right and I am honouring it: `norm_sum_Ico_cpow_le_of_lt_one`
is a true statement about partial sums of the Dirichlet series, and it is **false** as a statement
about `ζ` in the strip. Using it as if it bounded `ζ` would produce precisely the "true of the
series, false of ζ" theorem the note warns against.

**Route (a) is correct but blocked on three separate gaps, each verified:**
1. **`Complex.Gamma` growth.** The functional equation
   `riemannZeta_one_sub` gives `ζ(1-s) = 2(2π)^{-s} Γ(s) cos(πs/2) ζ(s)`, so bounding `ζ` on
   `0 ≤ Re s ≤ 1/2` requires `|Γ(σ+it)|` growth in `t`. Mathlib's `Stirling.lean` is 272 lines
   about `n!` for `n : ℕ` (`factorial_isEquivalent_stirling`); there is **no** complex Gamma
   asymptotics and no `|Γ(σ+it)|` bound at all.
2. **Bounding `ζ` on `Re s ≥ 1/2` from the other side.** The functional equation maps the strip
   to itself, so it does not by itself produce a bound; one needs `ζ` bounded on a half-plane to
   the *right* of the pole, which is the pole bound plus a strip bound — circular unless one
   splits at `Re s = 1+δ`.
3. **Phragmén–Lindelöf with an `O(log)` (not `O(z^c)`) boundary condition.**
   `PhragmenLindelof.vertical_strip` exists and is usable, but its hypothesis is
   `f =O[comap (|im ·|) atTop] exp(B * exp(c * |im|))` — it controls functions growing at most
   like `exp(exp(c|t|))`, and gives `‖f‖ ≤ C` (a *bounded* conclusion). Getting `O(log)` rather
   than `O(1)` requires the three-lines convexity argument (`ConvexOn` of
   `log ‖f‖` on the strip), for which Mathlib has the pieces (`norm_le_of_forall_mem_frontier_norm_le`,
   `PhragmenLindelof.vertical_strip`) but no assembled `log`-convexity theorem for `ζ`.

**Therefore: the functional-equation route needs machinery Mathlib lacks, and route (b) is
blocked by the absence of a finite-sum continuation identity.** I am saying this now rather than
after a long attempt, as asked.

What *is* delivered unconditionally is the pole bound (Target 2), which is the one of the three
missing inputs that the engine plus Mathlib actually supports. Of the three inputs the earlier
report listed, item 2 is now proved; items 1 and 3 remain open, and item 1 is blocked on complex
Gamma asymptotics rather than on Euler–Maclaurin.

## What is **not** proved, and exactly why

The target statement

```lean
∃ c > 0, ∀ s : ℂ, 1 - c / Real.log (|s.im| + 2) < s.re → riemannZeta s ≠ 0
```

with **c absolute** is *not* proved, and is not reachable with the tools that
exist at this Mathlib commit. The constant produced above depends on `H`, and
must: zeros become denser as `|Im s| → ∞`, so any constant valid on all heights
is bounded by the behaviour at every height.

Closing the absolute gap needs three quantitative inputs, none of which is in
Mathlib:

1. `‖ζ(σ + it)‖ ≤ C log(|t| + 2)` uniformly on the **open** strip `1/2 ≤ σ < 1`.
   **Open.** Blocked on complex Gamma asymptotics (see the routing section above); the engine's
   partial-sum bounds do not apply to `ζ` itself.
2. `Re ζ(σ) ≤ C / (σ - 1)` for `σ ∈ (1, 2)`. **DONE** — `Zeta.PoleBound`.
3. A local bound `‖ζ(σ + iγ)‖ ≤ C‖σ - β‖` at a zero `β + iγ`. **Open.**


Mathlib has no Euler–Maclaurin summation, no argument principle, no Rouché
theorem, and no explicit zero counting, which is why the target region is out of
reach here. The 3-4-1 inequality in `Zeta.ThreeFourOne` is exactly the consumer
that these three inputs would plug into.

### PNT error term

Not attempted beyond what is stated. Mathlib `master` at this commit has only
the first-order PNT (`Nat.isEquivalent_primeCounting`, `Chebyshev.isEquivalent_theta_id`)
and no `Li(x)`. A quantified error term `π(x) = Li(x) + O(x e^{-c√log x})`
additionally requires a Perron-type explicit formula and contour estimates, on
top of items 1–3 above. None of that machinery exists, so no error term is
claimed.
