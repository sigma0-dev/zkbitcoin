use std::{
  hash::Hash, cmp::Eq, 
  collections::{HashMap, VecDeque},
};

pub struct CappedHashMap<K, V>
where
  K: Hash + Eq + Copy + Clone
{
  inner: HashMap<K, V>,
  last_tasks: VecDeque<K>,
}

impl <K, V> CappedHashMap <K, V>
where
  K: Hash + Eq + Copy + Clone,
{
  const MAX_LEN: usize = 100;

  pub fn new() -> Self {
    Self {
      inner: HashMap::with_capacity(Self::MAX_LEN),
      last_tasks: VecDeque::with_capacity(Self::MAX_LEN),
    }
  }

  /// Inserts an new item to the collection. Return Some(key) where key is the 
  /// key that was removed when we reach the max capacity. Otherwise returns None.
  pub fn insert(&mut self, k: K, v: V) -> Option<K> {
    self.last_tasks.push_front(k);

    if self.last_tasks.len() == Self::MAX_LEN {
      // remove the oldest item. We an safely unwrap because we know the vec is no empty at this point
      let key = self.last_tasks.pop_back().unwrap();
      self.inner.remove(&key);

      return Some(key)
    }
    
    self.inner.insert(k, v);
    
    None
  }
}
