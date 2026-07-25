use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
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
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    Ok(argon2
        .hash_password(password.as_bytes(), &salt)?
        .to_string())
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
