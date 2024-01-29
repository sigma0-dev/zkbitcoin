use std::{
    cmp::Eq,
    collections::{HashMap, VecDeque},
    hash::Hash,
};

pub struct CappedHashMap<K, V>
where
    K: Hash + Eq + Copy + Clone,
{
    inner: HashMap<K, V>,
    last_items: VecDeque<K>,
}

impl<K, V> CappedHashMap<K, V>
where
    K: Hash + Eq + Copy + Clone,
{
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: HashMap::with_capacity(capacity),
            last_items: VecDeque::with_capacity(capacity),
        }
    }

    /// Inserts an new item to the collection. Return Some(key) where key is the
    /// key that was removed when we reach the max capacity. Otherwise returns None.
    pub fn insert(&mut self, k: K, v: V) -> Option<K> {
        let mut ret = None;
        let new_key = !self.inner.contains_key(&k);

        if new_key && self.last_items.len() >= self.last_items.capacity() {
            // remove the oldest item. We an safely unwrap because we know the last_items is not empty at this point
            let key = self.last_items.pop_back().unwrap();
            assert!(self.remove(&key).is_some());

            ret = Some(key);
        }

        // replacing a value should not push any new items to last_items
        if self.inner.insert(k, v).is_none() {
            self.last_items.push_front(k);
        }

        ret
    }

    /// Removes a key from the map, returning the value at the key if the key was previously in the map.
    pub fn remove(&mut self, k: &K) -> Option<V> {
        let Some(v) = self.inner.remove(k) else {
            return None;
        };

        self.last_items
            .iter()
            .position(|key| key == k)
            .and_then(|pos| self.last_items.remove(pos));

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
        let mut col: CappedHashMap<u8, u8> = CappedHashMap::new(10);
        col.insert(1, 1);
        col.insert(2, 2);
        col.insert(3, 3);

        assert_eq!(*col.get(&1).unwrap(), 1);
        assert_eq!(*col.get(&2).unwrap(), 2);
        assert_eq!(*col.get(&3).unwrap(), 3);
    }

    #[test]
    fn test_insert_should_return_removed_key() {
        // The real capacity will be 14. Read here for how this is calculated https://stackoverflow.com/a/76114888/512783
        let mut col: CappedHashMap<u8, u8> = CappedHashMap::new(10);

        for i in 0..10 {
            col.insert(i, i);
        }

        for i in 10..30 {
            // the nth oldest key will be removed
            let key_removed = col.insert(i, i);
            // our hashmap and vecqueue should never grow i.e. capacity doesn't change
            assert_eq!(col.last_items.capacity(), 10);

            assert!(key_removed.is_some());
            assert_eq!(key_removed.unwrap(), i - 10);
            assert_eq!(col.size(), 10);
        }

        // Not that we should have the last 10 keys in the collection i.e. 20-30. All the previous
        // were replaced by these new ones
        for i in 0..20 {
            assert!(col.get(&i).is_none());
        }

        // after cyclic inserts we still have a full capacity collection. We can remove one item...
        assert!(col.remove(&20).is_some());
        assert_eq!(col.size(), 9);

        // ... and now inserting a new item will not replace any existing one
        assert!(col.insert(31, 31).is_none());
    }

    #[test]
    fn test_insert_duplicate() {
        let mut col: CappedHashMap<u8, u8> = CappedHashMap::new(10);

        for i in 0..10 {
            col.insert(i, i);
        }

        assert_eq!(*col.get(&0).unwrap(), 0);
        assert_eq!(col.size(), 10);

        // replacing should simply replace the value and not affect the size.
        // so altough our col is full capacity, replacing an existing should not remove the oldest item
        assert!(col.insert(0, 2).is_none());
        assert_eq!(*col.get(&0).unwrap(), 2);
        assert_eq!(col.size(), 10);

        // but inserting a new one should
        let key_removed = col.insert(10, 10);
        assert!(key_removed.is_some());
        assert_eq!(key_removed.unwrap(), 0);
        assert_eq!(col.size(), 10);
    }

    #[test]
    fn test_remove() {
        let mut col: CappedHashMap<u8, u8> = CappedHashMap::new(10);

        for i in 0..10 {
            col.insert(i, i);
        }

        for i in 0..10 {
            let v = col.remove(&i);
            assert!(v.is_some());
            assert_eq!(v.unwrap(), i);
            assert_eq!(col.size() as u8, 10 - i - 1);
        }

        // the collection is empty so the next remove should return None
        let v = col.remove(&0);
        assert!(v.is_none());
    }
}
