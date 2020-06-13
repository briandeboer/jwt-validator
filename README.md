# JWT Validator

Validates a JWT and provides the claims (for actix web).

## Usage
In your fn main, supply the cert urls that you want to use to decode tokens.

```rust
#[actix_rt::main]
async fn main() -> io::Result<()> {
  ...
  let mut certs = CertSources::new(vec![
    "https://www.googleapis.com/oauth2/v2/certs".to_string(),
    ...
  ]);
  let _cert_result = certs.build_keys().await;
  let certs_client = Arc::new(certs);
  HttpServer::new(move || {
    App::new()
      .data(certs_client.clone())
      ...
  ...
}
```

Then in the handler that you want to check for the claims add a check...

```rust
pub async fn index(claims: Option<Claims>) -> HttpResponse {
  if claims.is_none()
    || claims.unwrap().validate(TestClaims {
      hd: Some("domain.com".to_string()),
      ..TestClaims::default()
    })
  {
    return HttpResponse::Unauthorized().body("Invalid request");
  }
  ...
  HttpResponse::Ok()
    .content_type("text/html; charset=utf-8")
    .body(html)
}
