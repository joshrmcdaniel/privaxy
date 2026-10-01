//! Capabilities for the reserved `/__privaxy__/gm/*` endpoints.
//!
//! Each matched userscript receives a token signing its script ID, page URL,
//! and origin. Endpoints verify that capability and recheck that the script is
//! still active and matches the signed page, rather than the reserved path.
//!
//! Tokens are not secrets from page code: userscripts run in the main world,
//! and a page can fetch its own rewritten HTML. A token therefore authorizes
//! only the script injected there; it cannot borrow another script's storage
//! or `@connect` permissions. The fetch relay also enforces address filtering.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use url::Url;

type HmacSha256 = Hmac<Sha256>;

// A new domain also rejects legacy tokens that authorized only an origin.
const TOKEN_DOMAIN: &[u8] = b"privaxy-userscript-endpoint-v2";

fn signature(origin: &str, script_id: &str, page: &str, signing_key: &str) -> HmacSha256 {
    let mut mac =
        HmacSha256::new_from_slice(signing_key.as_bytes()).expect("HMAC accepts any key length");
    for field in [
        TOKEN_DOMAIN,
        origin.as_bytes(),
        script_id.as_bytes(),
        page.as_bytes(),
    ] {
        mac.update(field);
        mac.update(b"\0");
    }
    mac
}

/// Issue a capability only after `script_id` has matched `page_url`.
pub fn mint(page_url: &Url, script_id: &str, signing_key: &str) -> String {
    let page = URL_SAFE_NO_PAD.encode(page_url.as_str());
    let mac = signature(
        &page_url.origin().ascii_serialization(),
        script_id,
        &page,
        signing_key,
    );
    format!(
        "{page}.{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    )
}

/// Verify the script and requesting origin, then return the authenticated page
/// URL so the caller can recheck the script's current matching rules.
pub fn verify(token: &str, origin: &str, script_id: &str, signing_key: &str) -> Option<Url> {
    let (page, supplied_signature) = token.split_once('.')?;
    let supplied_signature = URL_SAFE_NO_PAD.decode(supplied_signature).ok()?;
    signature(origin, script_id, page, signing_key)
        .verify_slice(&supplied_signature)
        .ok()?;

    let page = URL_SAFE_NO_PAD.decode(page).ok()?;
    let page_url = Url::parse(std::str::from_utf8(&page).ok()?).ok()?;
    (page_url.origin().ascii_serialization() == origin).then_some(page_url)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "0123456789abcdef0123456789abcdef";
    const SCRIPT: &str = "a.user.js";

    fn page() -> Url {
        Url::parse("https://example.com/watch?id=123").unwrap()
    }

    #[test]
    fn token_authenticates_the_matching_page() {
        let token = mint(&page(), SCRIPT, KEY);
        assert_eq!(
            verify(&token, "https://example.com", SCRIPT, KEY),
            Some(page())
        );
    }

    #[test]
    fn tokens_do_not_transfer_between_scripts_or_origins() {
        let token = mint(&page(), SCRIPT, KEY);
        assert!(verify(&token, "https://example.com", "b.user.js", KEY).is_none());
        for origin in [
            "https://evil.test",
            "http://example.com",
            "https://example.com:8443",
            "https://sub.example.com",
        ] {
            assert!(verify(&token, origin, SCRIPT, KEY).is_none());
        }
    }

    #[test]
    fn tokens_do_not_verify_under_a_different_key() {
        let token = mint(&page(), SCRIPT, KEY);
        assert!(verify(
            &token,
            "https://example.com",
            SCRIPT,
            "fedcba9876543210fedcba9876543210"
        )
        .is_none());
    }

    #[test]
    fn the_signed_page_cannot_be_changed() {
        let token = mint(&page(), SCRIPT, KEY);
        let (_, signature) = token.split_once('.').unwrap();
        let forged = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode("https://example.com/admin"),
            signature
        );
        assert!(verify(&forged, "https://example.com", SCRIPT, KEY).is_none());
    }

    #[test]
    fn malformed_and_legacy_tokens_are_rejected() {
        let mut legacy = HmacSha256::new_from_slice(KEY.as_bytes()).unwrap();
        legacy.update(b"privaxy-userscript-endpoint-v1\0https://example.com");
        let legacy = URL_SAFE_NO_PAD.encode(legacy.finalize().into_bytes());
        for candidate in ["", "x", "not-a-token-at-all", "bad.bad", &legacy] {
            assert!(verify(candidate, "https://example.com", SCRIPT, KEY).is_none());
        }
    }
}
