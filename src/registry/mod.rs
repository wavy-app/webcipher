pub mod builder;

use std::collections::BTreeMap;

use jsonwebtoken::TokenData;
use prelude::Error;
use serde::Deserialize;

use crate::key_caches::remote::RemoteCache;
use crate::prelude;

type RemoteCaches<TPA> = BTreeMap<TPA, RemoteCache>;

#[derive(Default)]
pub struct KeyRegistry<TPA> {
    pub(crate) remote_caches: RemoteCaches<TPA>,
}

impl<TPA> KeyRegistry<TPA>
where
    TPA: Ord,
{
    pub fn remote_caches(&self) -> &RemoteCaches<TPA> {
        &self.remote_caches
    }

    pub fn remote_caches_mut(&mut self) -> &mut RemoteCaches<TPA> {
        &mut self.remote_caches
    }

    pub async fn decrypt<Claim, I>(
        &mut self,
        tpa: TPA,
        token: I,
        auto_refresh: bool,
    ) -> prelude::Result<TokenData<Claim>>
    where
        String: From<I>,
        Claim: for<'de> Deserialize<'de>,
    {
        let Self { remote_caches } = self;
        let tpa_remote_cache =
            remote_caches.get_mut(&tpa).ok_or(Error::unrecognized_tpa)?;

        tpa_remote_cache.decrypt(token, auto_refresh).await
    }
}
