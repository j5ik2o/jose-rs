//! Enumeration of JOSE algorithm implementation requirements.
//! Refers to the requirement levels defined in RFC 2119.

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq, Hash)]
pub enum Requirement {
  REQUIRED,
  RECOMMENDED,
  OPTIONAL,
}

mod algorithm;
mod algorithm_family;
#[macro_export]
macro_rules! algorithm_family {
    (add: { $( $x:tt ),* }) => {
        {
            use crate::jose::algorithm_family::AlgorithmFamily;
            let mut af = AlgorithmFamily::new();
            $( if ! af.add($x.clone()) { panic!(); };  )*
            af
        }
    };
    (combine: { $($x:tt ),* }) => {
        {
            use crate::jose::algorithm_family::AlgorithmFamily;
            let mut af = AlgorithmFamily::new();
            $( af.combine($x.clone()); )*
            af
        }
    };
}
