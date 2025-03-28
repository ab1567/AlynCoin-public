extern crate alloc;
use serde::{Serialize, Deserialize};


#[derive(Debug, Clone, Serialize, Deserialize)]
    pub column: usize,
    pub value: F,
}
