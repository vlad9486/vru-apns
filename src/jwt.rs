use std::time::Duration;

use jwt_simple::algorithms::ES256KeyPair;

pub struct T {
    state: Option<JwtInner>,
    key: ES256KeyPair,
}

struct JwtInner {
    token: String,
    expire: Duration,
}

impl T {
    pub fn new(es256_secret: &[u8; 32], key_id: &str) -> Result<Self, jwt_simple::Error> {
        let key = ES256KeyPair::from_bytes(es256_secret)?.with_key_id(key_id);
        Ok(T { state: None, key })
    }

    pub fn regenerate(&mut self, issuer: &str) -> String {
        use std::time::SystemTime;

        fn generate(issuer: &str, key: &ES256KeyPair) -> JwtInner {
            use jwt_simple::prelude::*;

            // Refresh your token no more than once every 20 minutes
            // and no less than once every 60 minutes.
            let valid_for = Duration::from_secs(30 * 60);
            let claims = Claims::create(valid_for).with_issuer(&issuer);
            let expire = claims.expires_at.unwrap().into();
            let token = key.sign(claims).unwrap();
            JwtInner { token, expire }
        }

        match &mut self.state {
            Some(s) => {
                let now = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap();
                if now > s.expire {
                    *s = generate(issuer, &self.key);
                }
                s.token.clone()
            }
            None => {
                let new = generate(issuer, &self.key);
                let token = new.token.clone();
                self.state = Some(new);
                token
            }
        }
    }
}
