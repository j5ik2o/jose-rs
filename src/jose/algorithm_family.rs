use std::collections::HashSet;
use std::hash::Hash;

#[derive(Debug, Clone)]
pub struct AlgorithmFamily<T> {
  pub(crate) values: HashSet<T>,
}

impl<T> AlgorithmFamily<T>
where
  T: Eq + Hash + Clone,
{
  pub fn new() -> Self {
    Self {
      values: HashSet::<T>::new(),
    }
  }

  pub fn combine(&mut self, other: Self) -> bool {
    self.add_all(&other.values.into_iter().collect::<Vec<_>>())
  }

  pub fn add(&mut self, alg: T) -> bool {
    self.values.insert(alg)
  }

  pub fn add_all(&mut self, algs: &[T]) -> bool {
    let mut result = true;
    for alg in algs.iter() {
      result = result && self.add(alg.clone());
    }
    result
  }

  pub fn remove(&mut self, alg: &T) -> bool {
    self.values.remove(alg)
  }

  pub fn remove_all(&mut self, algs: &[T]) -> bool {
    let mut result = true;
    for alg in algs.iter() {
      result = result && self.remove(alg);
    }
    result
  }

  pub fn retain_all(mut self, algs: &[T]) {
    self.values.retain(|e| algs.contains(e));
  }
}
