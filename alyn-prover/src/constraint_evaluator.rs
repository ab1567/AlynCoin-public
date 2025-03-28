use alyn_air::Air;
use alloc::vec::Vec;

pub struct ConstraintEvaluator<'a, A: Air> {
    pub composition_coefficients: Vec<A::BaseField>,
    pub _marker: core::marker::PhantomData<&'a A>,
}

impl<'a, A: Air> ConstraintEvaluator<'a, A> {
    pub fn new(composition_coefficients: Vec<A::BaseField>) -> Self {
        ConstraintEvaluator {
            composition_coefficients,
            _marker: core::marker::PhantomData,
        }
    }
}
