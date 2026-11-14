use argon2::password_hash::{phc::PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::Argon2;
use openssl::rand::rand_bytes;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Default)]
pub struct Auth {
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password_hash: Option<String>,
    #[serde(default)]
    pub api_key: String,
    #[serde(default)]
    pub session_signing_key: String,
}

impl Auth {
    pub fn new_initialized() -> Self {
        Self {
            username: None,
            password_hash: None,
            api_key: generate_random_hex(32),
            session_signing_key: generate_random_hex(64),
        }
    }

    pub fn is_set_up(&self) -> bool {
        self.username.is_some() && self.password_hash.is_some()
    }

    pub fn verify_credentials(&self, username: &str, password: &str) -> bool {
        let stored_username = match &self.username {
            Some(u) => u,
            None => return false,
        };
        let stored_hash = match &self.password_hash {
            Some(h) => h,
            None => return false,
        };
        if stored_username != username {
            return false;
        }
        verify_password(password, stored_hash)
    }
}

pub fn generate_random_hex(num_bytes: usize) -> String {
    let mut buf = vec![0u8; num_bytes];
    rand_bytes(&mut buf).expect("OpenSSL random byte generation failed");
    hex::encode(buf)
}

pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let argon2 = Argon2::default();
    Ok(argon2.hash_password(password.as_bytes())?.to_string())
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    let parsed_hash = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passwords_saved_with_argon2_05_still_verify() {
        // A PHC test vector from argon2 0.5.3, with parameters stored in the hash.
        let hash =
            "$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4";
        assert!(verify_password("password", hash));
        assert!(!verify_password("wrong password", hash));
        assert!(!verify_password("password", "invalid PHC string"));
    }

    #[test]
    fn new_password_hashes_have_independent_salts_and_verify() {
        let first = hash_password("new test password").unwrap();
        let second = hash_password("new test password").unwrap();
        assert_ne!(first, second);
        assert!(verify_password("new test password", &first));
        assert!(verify_password("new test password", &second));
        assert!(!verify_password("different password", &first));
    }
}
