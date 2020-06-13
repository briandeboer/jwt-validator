use futures::stream::StreamExt;
use jsonwebtoken::{
    decode, decode_header,
    errors::{Error, ErrorKind},
    Validation,
};
use log::{debug, info, warn};

mod certs;
mod claims;

pub use claims::{Claims, TestClaims};

use crate::certs::{build_source, DecodedKey};
use serde::de::DeserializeOwned;
use std::collections::HashMap;

pub struct CertSources {
    sources: Vec<String>,
    keys: HashMap<String, DecodedKey>,
}

impl CertSources {
    pub fn new(sources: Vec<String>) -> Self {
        CertSources {
            sources,
            keys: HashMap::new(),
        }
    }

    pub async fn build_keys(&mut self) -> Result<(), Error> {
        let all_keys = futures::stream::iter(self.sources.iter())
            .fold(vec![], |mut acc, source| async move {
                debug!("building source {}", source);
                let result = build_source(source).await;
                match result {
                    Ok(mut inserted_keys) => {
                        info!("Successfully decoded keys for {}", source);
                        acc.append(&mut inserted_keys);
                    }
                    Err(e) => warn!("Unable to retrieve keys for {}, {}", source, e),
                };
                return acc;
            })
            .await;
        all_keys.iter().for_each(|key| {
            self.keys.insert(key.0.clone(), key.1.clone());
        });
        Ok(())
    }

    pub fn update_keys(&self) -> Result<bool, Error> {
        Ok(true)
    }

    pub fn validate_token<T: DeserializeOwned>(&self, token: &str) -> Result<T, Error> {
        let header = decode_header(token)?;

        let kid = header.kid.unwrap();
        let some_key = self.keys.get(&kid);

        match some_key {
            Some(decoded_key) => match &decoded_key.key {
                Some(key) => {
                    let token_data = decode::<T>(&token, key, &Validation::new(header.alg))?;
                    Ok(token_data.claims)
                }
                None => Err(Error::from(ErrorKind::InvalidKeyFormat)),
            },
            None => Err(Error::from(ErrorKind::InvalidToken)),
        }
    }
}
