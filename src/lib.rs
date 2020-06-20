#[macro_use]
extern crate lazy_static;

use async_std::task;
use futures::stream::StreamExt;
use jsonwebtoken::{
    decode, decode_header,
    errors::{Error, ErrorKind},
    Validation,
};
use log::{debug, info, warn};
use std::sync::{Mutex, MutexGuard};

mod certs;
mod claims;

const CAPACITY: usize = 10000;

lazy_static! {
    static ref CERT_KEYS: Mutex<HashMap<String, DecodedKey>> =
        Mutex::new(HashMap::with_capacity(CAPACITY));
}

fn get_cert_keys<'a>() -> MutexGuard<'a, HashMap<String, DecodedKey>> {
    CERT_KEYS.lock().unwrap()
}

pub use claims::{Claims, TestClaims};

use crate::certs::{build_source, DecodedKey};
use serde::de::DeserializeOwned;
use std::collections::HashMap;

#[derive(Clone)]
pub struct CertSources {
    sources: Vec<String>,
}

impl CertSources {
    pub fn new(sources: Vec<String>) -> Self {
        let certs = CertSources { sources };
        certs
    }

    pub async fn build_keys(&self) -> Result<(), Error> {
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
        {
            let mut cert_keys = get_cert_keys();
            all_keys.iter().for_each(|key| {
                cert_keys.insert(key.0.clone(), key.1.clone());
            });
        }
        Ok(())
    }

    pub fn update_keys(&self) -> Result<bool, Error> {
        Ok(true)
    }

    fn insert_placeholder_for_kid(&self, kid: &str) {
        let mut cert_keys = get_cert_keys();
        cert_keys.insert(kid.to_string(), DecodedKey::new());
    }

    pub fn validate_token<T: DeserializeOwned + std::fmt::Debug>(
        &self,
        token: &str,
    ) -> Result<T, Error> {
        let header = decode_header(token)?;

        let kid = header.kid.unwrap_or("unknown".to_string());
        let cert_keys = {
            let cert_keys = get_cert_keys();
            cert_keys.clone()
        };
        let some_key = cert_keys.get(&kid);
        match some_key {
            Some(decoded_key) => match &decoded_key.key {
                Some(key) => {
                    let token_data = decode::<T>(&token, key, &Validation::new(header.alg))?;
                    Ok(token_data.claims)
                }
                None => {
                    // check if we need to update key
                    if decoded_key.should_update() {
                        info!("Decoded key is checking again - maybe certs need to be updated");
                        // the kid might have been found before but wasn't updated
                        self.insert_placeholder_for_kid(&kid);
                        task::block_on(async {
                            let _result = self.build_keys().await;
                        });
                        let claims_result = self.validate_token(token);
                        match &claims_result {
                            Ok(_claims) => claims_result,
                            Err(_) => {
                                info!("Certs were updated but this token is still not working");
                                Err(Error::from(ErrorKind::InvalidToken))
                            }
                        }
                    } else {
                        Err(Error::from(ErrorKind::InvalidKeyFormat))
                    }
                }
            },
            None => {
                // the kid was not found
                info!("JWT kid {:?} was not found - rechecking certs", &kid);
                self.insert_placeholder_for_kid(&kid);
                task::block_on(async {
                    let _result = self.build_keys().await;
                });
                let claims_result = self.validate_token(token);
                match &claims_result {
                    Ok(_claims) => claims_result,
                    Err(_) => {
                        warn!("JWT kid {:?} still not found", &kid);
                        Err(Error::from(ErrorKind::InvalidToken))
                    }
                }
            }
        }
    }
}
