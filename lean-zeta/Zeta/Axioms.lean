import Zeta

/-! Axiom audit for the main results.

Run with `lake env lean Zeta/Axioms.lean`. Every line must report exactly
`[propext, Classical.choice, Quot.sound]`. -/

#print axioms Zeta.three_add_four_cos_add_cos_two
#print axioms Zeta.riemannZeta_norm_product_ge_one
#print axioms Zeta.riemannZeta_norm_le_re
#print axioms Zeta.riemannZeta_inv_norm_ge_inv_re
#print axioms Zeta.riemannZeta_inv_pow_le
#print axioms Zeta.isCompact_strip
#print axioms Zeta.exists_zero_free_height_local
#print axioms Zeta.exists_zero_free_strip_height_local
