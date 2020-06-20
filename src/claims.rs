use actix_web::error::ErrorBadRequest;
use actix_web::{dev, web::Data, Error, FromRequest, HttpRequest};
use futures_util::future::{err, ok, Ready};
use log::warn;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::CertSources;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Claims {
    pub aud: String,
    email: Option<String>,
    exp: usize,
    pub hd: Option<String>,
    iat: usize,
    pub iss: String,
    jti: String,
    locale: Option<String>,
    name: Option<String>,
    pub sub: String,
}

#[derive(Default, Debug)]
pub struct TestClaims {
    pub aud: Option<String>,
    pub email: Option<String>,
    pub hd: Option<String>,
    pub iss: Option<String>,
    pub locale: Option<String>,
    pub name: Option<String>,
    pub sub: Option<String>,
}

impl Claims {
    pub fn validate(&self, test: TestClaims) -> bool {
        if test.aud.map_or(false, |t| t != self.aud) {
            return false;
        }
        if test.email.is_some() && test.email != self.email {
            return false;
        }
        if test.hd.is_some() && test.hd != self.hd {
            return false;
        }
        if test.iss.map_or(false, |t| t != self.iss) {
            return false;
        }
        if test.locale.is_some() && test.locale != self.locale {
            return false;
        }
        if test.name.is_some() && test.name != self.name {
            return false;
        }
        if test.sub.map_or(false, |t| t != self.sub) {
            return false;
        }
        return true;
    }
}

impl FromRequest for Claims {
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;
    type Config = ();

    fn from_request(req: &HttpRequest, _payload: &mut dev::Payload) -> Self::Future {
        let re = Regex::new(r"(Bearer\s)?(?P<token>.*)").unwrap();

        let some_creds = req.headers().get("Authorization");
        match some_creds {
            Some(credentials) => {
                let token = re.replace_all(credentials.to_str().unwrap(), "$token");
                let certs = req.app_data::<Data<Arc<CertSources>>>().unwrap();
                let result: Result<Claims, _> = certs.validate_token(&token);
                match result {
                    Ok(claims) => ok(claims),
                    Err(e) => {
                        warn!("Bad credentials {}", e);
                        err(ErrorBadRequest("Forbidden request"))
                    }
                }
            }
            None => err(ErrorBadRequest("Forbidden request")),
        }
    }
}
