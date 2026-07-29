//! Authorization for the reserved `/__privaxy__/gm/*` endpoints.
//!
//! Userscripts run in the page's main world, so anything they need must be
//! reachable from page context — and a page cannot send credentials to the
//! Privaxy origin without CORS, which this codebase deliberately does not
//! enable. The endpoints are therefore served on *the page's own origin*,
//! intercepted by the proxy, and authorized by a token minted at injection time.
//!
//! # What the token does and does not buy
//!
//! The token is an HMAC over the page's origin. It means the endpoints only
//! answer for origins where Privaxy actually injected userscripts, so an
//! arbitrary site cannot reach them at all.
//!
//! It is **not** a secret kept from the page. Inline script text is readable via
//! the DOM, so a hostile page sharing an origin with an injected script could in
//! principle recover the token. Two things limit that: the runtime blanks its own
//! element's text as soon as it has started (and, being injected at the top of
//! `<head>`, it runs before any of the page's own scripts get the chance to
//! read it), and the token is bound to one origin so it is useless elsewhere.
//! Anything reachable through these endpoints must therefore be safe to expose
//! to the origins the operator installed scripts for — which is why the fetch
//! relay enforces its own `@connect` allow-list on top of this.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Domain separator so a userscript token can never be confused with — or
/// derived from the same input as — a session cookie signature, even though
/// both ultimately derive from `auth.session_signing_key`.
const TOKEN_DOMAIN: &[u8] = b"privaxy-userscript-endpoint-v1";

/// Mint the token for `origin` (scheme + host + optional port, exactly as the
/// page sees it).
pub fn mint(origin: &str, signing_key: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(signing_key.as_bytes()).expect("HMAC accepts any key length");
    mac.update(TOKEN_DOMAIN);
    mac.update(b"\0");
    mac.update(origin.as_bytes());

    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

/// Whether `token` was minted for `origin`.
pub fn verify(token: &str, origin: &str, signing_key: &str) -> bool {
    let expected = mint(origin, signing_key);

    // Constant-time comparison: a byte-at-a-time early return would leak how
    // much of a guessed token was correct.
    if expected.len() != token.len() {
        return false;
    }

    expected
        .bytes()
        .zip(token.bytes())
        .fold(0u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn a_minted_token_verifies_for_its_own_origin() {
        let token = mint("https://example.com", KEY);

        assert!(verify(&token, "https://example.com", KEY));
    }

    /// The whole point of binding: a token handed to one site must be useless
    /// on another, including a same-host different-scheme or different-port
    /// origin.
    #[test]
    fn tokens_do_not_transfer_between_origins() {
        let token = mint("https://example.com", KEY);

        assert!(!verify(&token, "https://evil.test", KEY));
        assert!(!verify(&token, "http://example.com", KEY));
        assert!(!verify(&token, "https://example.com:8443", KEY));
        assert!(!verify(&token, "https://sub.example.com", KEY));
    }

    #[test]
    fn tokens_do_not_verify_under_a_different_key() {
        let token = mint("https://example.com", KEY);

        assert!(!verify(
            &token,
            "https://example.com",
            "fedcba9876543210fedcba9876543210"
        ));
    }

    #[test]
    fn malformed_tokens_are_rejected() {
        for candidate in ["", "x", "not-a-token-at-all"] {
            assert!(
                !verify(candidate, "https://example.com", KEY),
                "{candidate:?} must not verify"
            );
        }
    }

    /// Session signatures and endpoint tokens both derive from the same
    /// configured key; the domain separator must keep them distinct.
    #[test]
    fn token_is_domain_separated_from_a_bare_hmac() {
        let mut mac = HmacSha256::new_from_slice(KEY.as_bytes()).unwrap();
        mac.update(b"https://example.com");
        let undomained = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());

        assert_ne!(mint("https://example.com", KEY), undomained);
    }
}
