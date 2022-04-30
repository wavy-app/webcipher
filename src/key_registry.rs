use std::collections::HashMap;
use std::ops::Deref;
use std::ops::DerefMut;

use crate::key_store::KeyStore;

pub struct KeyRegistry<K> {
    pub(crate) stores: HashMap<K, KeyStore>,
}

impl<K> Deref for KeyRegistry<K> {
    type Target = HashMap<K, KeyStore>;

    fn deref(&self) -> &Self::Target {
        &self.stores
    }
}

impl<K> DerefMut for KeyRegistry<K> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.stores
    }
}
