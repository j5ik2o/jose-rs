use std::str::FromStr;

use once_cell::sync::Lazy;
use serde::Deserialize;
use serde::Serialize;

use jws::family::SIGNATURE;

use crate::jose::Requirement;

pub trait AlgorithmBehavior {
  fn name(&self) -> String;
  fn requirement(&self) -> Option<Requirement>;
  fn to_json_string(&self, pretty: bool) -> String;
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct Algorithm {
  name: String,
  requirement: Option<Requirement>,
}

pub enum AlgorithmError {
  NotFoundError,
}

impl FromStr for Algorithm {
  type Err = AlgorithmError;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    if s == NONE.name {
      Ok(NONE.clone())
    } else {
      match SIGNATURE.values.clone().into_iter().find(|e| e.name() == s) {
        Some(entry) => Ok(entry),
        None => Err(AlgorithmError::NotFoundError)
      }
    }
  }
}

impl AlgorithmBehavior for Algorithm {
  fn name(&self) -> String {
    self.name.clone()
  }

  fn requirement(&self) -> Option<Requirement> {
    self.requirement.clone()
  }

  fn to_json_string(&self, pretty: bool) -> String {
    if pretty {
      serde_json::to_string_pretty(self).unwrap()
    } else {
      serde_json::to_string(self).unwrap()
    }
  }
}

impl Algorithm {
  pub fn new(name: &str, requirement: Option<Requirement>) -> Self {
    Self {
      name: name.to_string(),
      requirement,
    }
  }
}

pub static NONE: Lazy<Algorithm> = Lazy::new(|| Algorithm::new("none", Some(Requirement::REQUIRED)));

pub mod jws {
  use super::*;

  pub static HS256: Lazy<Algorithm> = Lazy::new(|| Algorithm::new("HS256", Some(Requirement::OPTIONAL)));

  pub static HS384: Lazy<Algorithm> = Lazy::new(|| Algorithm::new("HS384", Some(Requirement::OPTIONAL)));

  pub static HS512: Lazy<Algorithm> = Lazy::new(|| Algorithm::new("HS512", Some(Requirement::OPTIONAL)));

  pub static RS256: Lazy<Algorithm> = Lazy::new(|| Algorithm::new("RS256", Some(Requirement::RECOMMENDED)));

  pub static RS384: Lazy<Algorithm> = Lazy::new(|| Algorithm::new("RS384", Some(Requirement::OPTIONAL)));

  pub static RS512: Lazy<Algorithm> = Lazy::new(|| Algorithm::new("RS512", Some(Requirement::OPTIONAL)));

  pub static ES256: Lazy<Algorithm> = Lazy::new(|| Algorithm::new("ES256", Some(Requirement::RECOMMENDED)));

  pub static ES256K: Lazy<Algorithm> = Lazy::new(|| Algorithm::new("ES256K", Some(Requirement::OPTIONAL)));

  pub static ES384: Lazy<Algorithm> = Lazy::new(|| Algorithm::new("ES384", Some(Requirement::OPTIONAL)));

  pub static ES512: Lazy<Algorithm> = Lazy::new(|| Algorithm::new("ES512", Some(Requirement::OPTIONAL)));

  pub static PS256: Lazy<Algorithm> = Lazy::new(|| Algorithm::new("PS256", Some(Requirement::OPTIONAL)));

  pub static PS384: Lazy<Algorithm> = Lazy::new(|| Algorithm::new("PS384", Some(Requirement::OPTIONAL)));

  pub static PS512: Lazy<Algorithm> = Lazy::new(|| Algorithm::new("PS512", Some(Requirement::OPTIONAL)));

  pub static ED_DSA: Lazy<Algorithm> = Lazy::new(|| Algorithm::new("EdDSA", Some(Requirement::OPTIONAL)));

  pub mod family {
    use once_cell::sync::Lazy;

    use crate::*;
    use crate::jose::algorithm::Algorithm;
    use crate::jose::algorithm::jws::*;
    use crate::jose::algorithm_family::AlgorithmFamily;

    pub static HMAC_SHA: Lazy<AlgorithmFamily<Algorithm>> =
      Lazy::new(|| algorithm_family! { add:{ HS256, HS384, HS512 } });

    pub static RSA: Lazy<AlgorithmFamily<Algorithm>> = Lazy::new(|| {
      algorithm_family! { add: { RS256, RS384, RS512, PS256, PS384, PS512 } }
    });

    pub static EC: Lazy<AlgorithmFamily<Algorithm>> = Lazy::new(|| {
      algorithm_family! { add: { ES256, ES256K, ES384, ES512 } }
    });

    pub static ED: Lazy<AlgorithmFamily<Algorithm>> = Lazy::new(|| {
      algorithm_family! { add: { ED_DSA } }
    });

    pub static SIGNATURE: Lazy<AlgorithmFamily<Algorithm>> = Lazy::new(|| {
      algorithm_family! { combine: { RSA, EC, ED } }
    });
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test() {
    let a = &NONE;
    println!("{}", a.to_json_string(true));
  }
}
