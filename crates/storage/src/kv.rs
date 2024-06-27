trait PreconfStore {
    fn get(&self, key: K) -> V;
    fn set(&self, key: K, value: V);
    fn delete(&self, key: K);
}
