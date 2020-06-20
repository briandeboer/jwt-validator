use jsonwebtoken::{errors::Error, errors::ErrorKind, DecodingKey};
use log::{debug, warn};
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::*;
use openssl::nid::Nid;
use serde::Deserialize;
use std::time::SystemTime;

const INTERVAL: u64 = 60; // how long do you wait if there was a failure

#[derive(Clone, Debug)]
pub struct DecodedKey {
    pub key: Option<DecodingKey<'static>>,
    pub updated: u64,
}

impl DecodedKey {
    pub fn new() -> Self {
        DecodedKey {
            key: None,
            updated: now(),
        }
    }
}

impl DecodedKey {
    pub fn should_update(&self) -> bool {
        now() - self.updated > INTERVAL
    }
}

#[derive(Debug, Clone, Deserialize)]
struct Certs {
    keys: Vec<CertDefinition>,
}

#[derive(Debug, Clone, Deserialize)]
struct CertDefinition {
    alg: Option<String>,
    kty: String,
    kid: String,
    n: Option<String>,
    r#use: Option<String>,
    e: Option<String>,
    crv: Option<String>,
    x: Option<String>,
    y: Option<String>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn get_bignum_from_base64(b64: &str) -> BigNum {
    let bytes = base64::decode_config(b64, base64::URL_SAFE).unwrap();
    BigNum::from_slice(&bytes).unwrap()
}

fn get_key_from_curve(crv: &str, x: &str, y: &str) -> Result<DecodingKey<'static>, Error> {
    if crv != "P-256" {
        return Err(Error::from(ErrorKind::InvalidKeyFormat));
    }

    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
        .map_err(|_e| Error::from(ErrorKind::InvalidEcdsaKey))?;
    let key = EcKey::from_public_key_affine_coordinates(
        &group,
        &get_bignum_from_base64(x),
        &get_bignum_from_base64(y),
    )
    .map_err(|_e| Error::from(ErrorKind::InvalidEcdsaKey))?;
    let mut ctx: BigNumContext = BigNumContext::new().unwrap();
    let key_bytes = key
        .public_key()
        .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)
        .map_err(|_e| Error::from(ErrorKind::InvalidEcdsaKey))?;
    let decoding_key = DecodingKey::from_ec_der(&key_bytes)?;
    Ok(decoding_key)
}

fn get_rsa_key_from_cert(cert: &CertDefinition) -> DecodedKey {
    if cert.n.is_some() && cert.e.is_some() {
        let key_result: Result<DecodingKey<'static>, _> =
            DecodingKey::from_rsa_components(&cert.n.clone().unwrap(), &cert.e.clone().unwrap());
        match key_result {
            Ok(decoding_key) => DecodedKey {
                key: Some(decoding_key),
                updated: now(),
            },
            Err(_) => {
                warn!("Unable to decode key for {}", cert.kty);
                DecodedKey {
                    key: None,
                    updated: now(),
                }
            }
        }
    } else {
        warn!("RSA kty must have `n` and `e` parameters");
        DecodedKey {
            key: None,
            updated: now(),
        }
    }
}

fn get_ec_key_from_cert(cert: &CertDefinition) -> DecodedKey {
    if cert.crv.is_some() && cert.x.is_some() && cert.y.is_some() {
        match cert.crv.clone().unwrap().as_str() {
            "P-256" => {
                let key_result =
                    get_key_from_curve("P-256", &cert.x.clone().unwrap(), &cert.y.clone().unwrap());
                match key_result {
                    Ok(decoding_key) => DecodedKey {
                        key: Some(decoding_key),
                        updated: now(),
                    },
                    Err(_) => {
                        warn!("Unable to decode key for {}", cert.kty);
                        DecodedKey {
                            key: None,
                            updated: now(),
                        }
                    }
                }
            }
            _ => {
                warn!("Only EC crv P-256 is supported at this time");
                DecodedKey {
                    key: None,
                    updated: now(),
                }
            }
        }
    } else {
        warn!("EC kty must have `crv`, `x` and `y` parameters");
        DecodedKey {
            key: None,
            updated: now(),
        }
    }
}

fn insert_keys_from_cert(cert_keys: Certs) -> Vec<(String, DecodedKey)> {
    let mut inserted_keys = vec![];
    cert_keys
        .keys
        .iter()
        .for_each(|cert| match cert.kty.as_str() {
            "RSA" => {
                inserted_keys.push((cert.kid.clone(), get_rsa_key_from_cert(cert)));
            }
            "EC" => {
                inserted_keys.push((cert.kid.clone(), get_ec_key_from_cert(cert)));
            }
            _ => {
                warn!("Unsupported kty type {}", cert.kty);
                inserted_keys.push((
                    cert.kid.clone(),
                    DecodedKey {
                        key: None,
                        updated: now(),
                    },
                ));
            }
        });
    inserted_keys
}

pub async fn build_source(source: &String) -> Result<Vec<(String, DecodedKey)>, Error> {
    let response = surf::get(source.clone());
    let cert_keys: Certs = response
        .recv_json()
        .await
        .map_err(|_e| Error::from(ErrorKind::InvalidSubject))?;
    let inserted_keys = insert_keys_from_cert(cert_keys);
    debug!("Inserted keys: {:?}", inserted_keys);
    Ok(inserted_keys)
}
