#![no_std]
extern crate alloc;

pub mod context;
pub mod proof;
pub mod evaluation_frame;
pub mod transition;
pub mod constraints;
pub mod traits;
pub mod transition_constraint;

pub use context::{TraceInfo, ConstraintCompositionCoefficients};
pub use crate::proof::StarkProof;
pub use evaluation_frame::EvaluationFrame;
pub use transition::TransitionConstraintGroup;
pub use traits::{Air, BoundaryConstraint};
