#[macro_use]
extern crate lazy_static;

use futures::stream::StreamExt;
use jsonwebtoken::errors::Error;

mod certs;
use crate::certs::{build_source, debug_keys};

pub struct CertSources {
    sources: Vec<String>,
}

const MAX_CONCURRENT: usize = 4;

impl CertSources {
    pub fn new(sources: Vec<String>) -> Self {
        CertSources { sources }
    }

    pub async fn build_keys(&self) -> Result<(), Error> {
        futures::stream::iter(self.sources.iter())
            .for_each_concurrent(MAX_CONCURRENT, |source| async move {
                build_source(source).await;
            })
            .await;
        Ok(())
    }

    pub fn update_keys(&self) -> Result<bool, Error> {
        Ok(true)
    }

    pub fn debug_keys(&self) {
        debug_keys();
    }

    pub fn validate_token(&self, _token: &str) {}
}
