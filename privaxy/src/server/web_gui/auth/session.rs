use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

pub const SESSION_TTL_SECS: u64 = 30 * 24 * 60 * 60;
pub const COOKIE_NAME: &str = "privaxy_session";

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionClaims {
    pub u: String,
    pub iat: u64,
    pub exp: u64,
}

pub fn issue_token(username: &str, signing_key: &str) -> String {
    let now = current_unix_secs();
    let claims = SessionClaims {
        u: username.to_string(),
        iat: now,
        exp: now + SESSION_TTL_SECS,
    };
    let payload_json = serde_json::to_vec(&claims).expect("claims serializable");
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json);
    let sig_b64 = sign(&payload_b64, signing_key);
    format!("{}.{}", payload_b64, sig_b64)
}

pub fn verify(token: &str, signing_key: &str) -> Result<SessionClaims, ()> {
    let mut parts = token.splitn(2, '.');
    let payload_b64 = parts.next().ok_or(())?;
    let sig_b64 = parts.next().ok_or(())?;
    let expected_sig = sign(payload_b64, signing_key);
    if !constant_time_eq(sig_b64.as_bytes(), expected_sig.as_bytes()) {
        return Err(());
    }
    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_b64).map_err(|_| ())?;
    let claims: SessionClaims = serde_json::from_slice(&payload_bytes).map_err(|_| ())?;
    if claims.exp <= current_unix_secs() {
        return Err(());
    }
    Ok(claims)
}

fn sign(payload_b64: &str, signing_key: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(signing_key.as_bytes()).expect("HMAC accepts any key length");
    mac.update(payload_b64.as_bytes());
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn extract_session_cookie(cookie_header: &str) -> Option<String> {
    cookie_header.split(';').map(str::trim).find_map(|crumb| {
        let (name, value) = crumb.split_once('=')?;

        if name == COOKIE_NAME {
            Some(value.to_string())
        } else {
            None
        }
    })
}

pub fn build_session_cookie(token: &str, secure: bool) -> String {
    let secure_attr = if secure { "; Secure" } else { "" };
    format!(
        "{name}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={ttl}{secure_attr}",
        name = COOKIE_NAME,
        token = token,
        ttl = SESSION_TTL_SECS,
    )
}

pub fn build_logout_cookie(secure: bool) -> String {
    let secure_attr = if secure { "; Secure" } else { "" };
    format!(
        "{name}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{secure_attr}",
        name = COOKIE_NAME,
    )
}
