// probes/context.rs
use std::collections::HashMap;

#[derive(Default, Clone)]
pub struct ProbeContext {
    pub params: HashMap<String, String>,
}

impl ProbeContext {
    pub fn get(&self, k: &str) -> Option<&String> {
        self.params.get(k)
    }
    pub fn insert(&mut self, k: impl Into<String>, v: impl Into<String>) {
        self.params.insert(k.into(), v.into());
    }
}
