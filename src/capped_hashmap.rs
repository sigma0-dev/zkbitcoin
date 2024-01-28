use std::{
    cmp::Eq,
    collections::{HashMap, VecDeque},
    hash::Hash,
};

pub struct CappedHashMap<K, V>
where
    K: Hash + Eq + Copy + Clone,
{
    capacity: usize,
    inner: HashMap<K, V>,
    last_tasks: VecDeque<K>,
}

impl<K, V> CappedHashMap<K, V>
where
    K: Hash + Eq + Copy + Clone,
{
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            inner: HashMap::with_capacity(capacity),
            last_tasks: VecDeque::with_capacity(capacity),
        }
    }

    /// Inserts an new item to the collection. Return Some(key) where key is the
    /// key that was removed when we reach the max capacity. Otherwise returns None.
    pub fn insert(&mut self, k: K, v: V) -> Option<K> {
        self.last_tasks.push_front(k);

        if self.last_tasks.len() == self.capacity {
            // remove the oldest item. We an safely unwrap because we know the last_tasks is not empty at this point
            let key = self.last_tasks.pop_back().unwrap();
            self.remove(&key);

            return Some(key);
        }

        self.inner.insert(k, v);

        None
    }

    /// Removes a key from the map, returning the value at the key if the key was previously in the map.
    pub fn remove(&mut self, k: &K) -> Option<V> {
        let Some(v) = self.inner.remove(k) else {
            return None;
        };

        self.last_tasks = self
            .last_tasks
            .iter()
            .filter(|key| *key != k)
            .map(|key| *key)
            .collect::<VecDeque<_>>();

        Some(v)
    }

    /// Returns a reference to the value corresponding to the key.
    pub fn get(&self, k: &K) -> Option<&V> {
      self.inner.get(k)
    }

    /// Returns a mutable reference to the value corresponding to the key.
    pub fn get_mut(&mut self, k: &K) -> Option<&mut V> {
      self.inner.get_mut(k)
    }
    
    /// Returns the number of elements in the collection
    pub fn size(&self) -> usize {
        self.inner.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_into_non_full_collection() {
        let mut col: CappedHashMap<&str, u8> = CappedHashMap::new(10);
        col.insert("key_1", 1);
        col.insert("key_2", 2);
        col.insert("key_3", 3);

        assert_eq!(*col.get(&"key_1").unwrap(), 1);
        assert_eq!(*col.get(&"key_2").unwrap(), 2);
        assert_eq!(*col.get(&"key_3").unwrap(), 3);
    }
}
