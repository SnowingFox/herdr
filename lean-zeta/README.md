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

1. `‖ζ(σ + it)‖ ≤ C log(|t| + 2)` uniformly for `σ ≥ 1/2` (Euler–Maclaurin /
   integral test over the Dirichlet series).
2. `Re ζ(σ) ≤ C / (σ - 1)` for `σ ∈ (1, 2)` (integral test; the pole bound).
3. A local bound `‖ζ(σ + iγ)‖ ≤ C‖σ - β‖` at a zero `β + iγ`.

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
