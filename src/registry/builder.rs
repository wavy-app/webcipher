use std::collections::BTreeMap;
use std::ops::Deref;
use std::ops::DerefMut;

use super::KeyRegistry;
use crate::key_caches::remote::RemoteCache;
use crate::prelude;

type Uris<Tpa> = BTreeMap<Tpa, String>;

pub struct KeyRegistryBuilder<Tpa> {
    uris: Uris<Tpa>,
}

impl<Tpa> Default for KeyRegistryBuilder<Tpa>
where
    Tpa: Ord,
{
    fn default() -> Self {
        let uris = BTreeMap::default();
        Self { uris }
    }
}

impl<Tpa> KeyRegistryBuilder<Tpa>
where
    Tpa: Ord,
{
    pub fn add_remote<I>(mut self, tpa: Tpa, uri: I) -> Self
    where
        String: From<I>,
    {
        let Self { uris } = &mut self;
        let uri = uri.into();

        uris.insert(tpa, uri);

        self
    }

    pub async fn build(self) -> prelude::Result<KeyRegistry<Tpa>> {
        let Self { uris } = self;

        let mut remote_caches = BTreeMap::default();

        for (tpa, uri) in uris {
            let remote_cache = RemoteCache::new(uri).await?;
            remote_caches.insert(tpa, remote_cache);
        }

        let key_registry = KeyRegistry { remote_caches };

        Ok(key_registry)
    }
}

impl<Tpa> Deref for KeyRegistryBuilder<Tpa> {
    type Target = Uris<Tpa>;

    fn deref(&self) -> &Self::Target {
        &self.uris
    }
}

impl<Tpa> DerefMut for KeyRegistryBuilder<Tpa> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.uris
    }
}
