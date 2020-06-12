use actix_web::client::Client;
use jsonwebtoken::{errors::Error, errors::ErrorKind, DecodingKey};
use log::warn;
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::*;
use openssl::nid::Nid;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::SystemTime;

// 1000 seems like a reasonable maximum number of keys to store
const CAPACITY: usize = 1000;

#[derive(Debug)]
struct DecodedKey {
    key: Option<DecodingKey<'static>>,
    updated: u64,
}

lazy_static! {
    static ref DECODING_KEYS: Mutex<HashMap<String, DecodedKey>> =
        Mutex::new(HashMap::with_capacity(CAPACITY));
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

fn insert_keys_from_cert(cert_keys: Certs) -> Vec<String> {
    let mut inserted_kids = vec![];
    let mut key_map = DECODING_KEYS.lock().unwrap();
    cert_keys
        .keys
        .iter()
        .for_each(|cert| match cert.kty.as_str() {
            "RSA" => {
                inserted_kids.push(cert.kid.clone());
                key_map.insert(cert.kid.clone(), get_rsa_key_from_cert(cert));
            }
            "EC" => {
                inserted_kids.push(cert.kid.clone());
                key_map.insert(cert.kid.clone(), get_ec_key_from_cert(cert));
            }
            _ => {
                warn!("Unsupported kty type {}", cert.kty);
                key_map.insert(
                    cert.kid.clone(),
                    DecodedKey {
                        key: None,
                        updated: now(),
                    },
                );
            }
        });
    inserted_kids
}

pub async fn build_source(source: &String) {
    let client = Client::default();
    let response = client.get(source.clone()).send().await;

    let cert_keys: Certs = response.unwrap().json().await.unwrap();
    insert_keys_from_cert(cert_keys);
}

pub fn debug_keys() {
    let key_map = DECODING_KEYS.lock().unwrap();
    println!("{:?}", key_map);
}
