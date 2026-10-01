use lazy_static::lazy_static;
use std::sync::{Arc, RwLock};
use wildmatch::WildMatch;

#[derive(Debug, Clone)]
struct WildMatchCollection(Vec<WildMatch>);

impl WildMatchCollection {
    fn new(patterns: Vec<String>) -> Self {
        Self(
            patterns
                .into_iter()
                .map(|pattern| {
                    // Making things case insensitive

                    let pattern_lowercase = pattern.to_lowercase();
                    WildMatch::new(&pattern_lowercase)
                })
                .collect(),
        )
    }

    fn is_match(&self, element: &str) -> bool {
        // Making things case insensitive
        let lowercase_element = element.to_lowercase();

        self.0
            .iter()
            .any(|pattern| pattern.matches(&lowercase_element))
    }
}

// Apple service exclusions, as defined in https://support.apple.com/en-us/HT210060.
// Shared with PAC generation so inclusion mode keeps the same precedence there.
pub(crate) const DEFAULT_EXCLUSION_PATTERNS: &[&str] = &[
    "*.apple.com",
    "static.ips.apple.com",
    "*.push.apple.com",
    "setup.icloud.com",
    "*.business.apple.com",
    "*.school.apple.com",
    "upload.appleschoolcontent.com",
    "ws-ee-maidsvc.icloud.com",
    "itunes.com",
    "appldnld.apple.com.edgesuite.net",
    "*.itunes.apple.com",
    "updates-http.cdn-apple.com",
    "updates.cdn-apple.com",
    "*.apps.apple.com",
    "*.mzstatic.com",
    "*.appattest.apple.com",
    "doh.dns.apple.com",
    "appleid.cdn-apple.com",
    "*.apple-cloudkit.com",
    "*.apple-livephotoskit.com",
    "*.apzones.com",
    "*.cdn-apple.com",
    "*.gc.apple.com",
    "*.icloud.com",
    "*.icloud.com.cn",
    "*.icloud.apple.com",
    "*.icloud-content.com",
    "*.iwork.apple.com",
    "mask.icloud.com",
    "mask-h2.icloud.com",
    "mask-api.icloud.com",
    "devimages-cdn.apple.com",
    "download.developer.apple.com",
];

lazy_static! {
    static ref DEFAULT_EXCLUSIONS: WildMatchCollection = WildMatchCollection::new(
        DEFAULT_EXCLUSION_PATTERNS
            .iter()
            .map(|host| host.to_string())
            .collect()
    );
}

/// Hosts the maintainer has observed to use certificate pinning, HSTS preload
/// plus strict TLS, or otherwise break under MITM interception. Exposed to the
/// web UI via the "Reset to defaults" button so users can opt in by populating
/// their own exclusions list. These are NOT applied automatically — see
/// `DEFAULT_EXCLUSIONS` above for the always-on Apple safety net.
pub fn recommended_exclusions() -> &'static [&'static str] {
    &[
        // AI providers
        "openai.com",
        "*.openai.com",
        "chatgpt.com",
        "*.chatgpt.com",
        "claude.ai",
        "*.claude.ai",
        "openrouter.ai",
        "*.openrouter.ai",
        // AWS WAF / DDoS providers
        "awswaf.com",
        "*.awswaf.com",
        "check.ddos-guard.net",
        // Identity / SSO
        "okta.com",
        "*.okta.com",
        // Banking / brokerage / payments
        "capitalone.com",
        "*.capitalone.com",
        "americanexpress.com",
        "*.americanexpress.com",
        "experian.com",
        "*.experian.com",
        "marcus.com",
        "*.marcus.com",
        "fidelity.com",
        "*.fidelity.com",
        "fmr.com",
        "*.fmr.com",
        "robinhood.com",
        "*.robinhood.com",
        "webull.com",
        "*.webull.com",
        "webullfintech.com",
        "*.webullfintech.com",
        "tradingview.com",
        "*.tradingview.com",
        "stripecdn.com",
        "*.stripecdn.com",
        "squarecdn.com",
        "*.squarecdn.com",
        "cashappapi.com",
        "*.cashappapi.com",
        // Mega
        "mega.nz",
        "*.mega.nz",
        "mega.co.nz",
        "*.mega.co.nz",
        // Retail / restaurants
        "homedepot.com",
        "*.homedepot.com",
        "pizzahut.com",
        "*.pizzahut.com",
        // Amazon
        "amazon.com",
        "*.amazon.com",
        "amazonaws.com",
        "*.amazonaws.com",
        "amazontrust.com",
        "*.amazontrust.com",
        // Social / messaging
        "instagram.com",
        "*.instagram.com",
        "facebook.com",
        "*.facebook.com",
        "snapchat.com",
        "*.snapchat.com",
        "snap.com",
        "*.snap.com",
        "snap.co",
        "*.snap.co",
        "sc-cdn.net",
        "*.sc-cdn.net",
        "signal.org",
        "*.signal.org",
        "proton.me",
        "*.proton.me",
        "protonmail.com",
        "*.protonmail.com",
        "twitter.com",
        "*.twitter.com",
        "x.com",
        "*.x.com",
        "t.co",
        "x.co",
        "wechat.com",
        "*.wechat.com",
        "discord.com",
        "*.discord.com",
        "discord.gg",
        "*.discord.gg",
        "discordapp.com",
        "*.discordapp.com",
        "discordstatus.com",
        "bumble.com",
        "*.bumble.com",
        // Carriers / shipping
        "t-mobile.com",
        "*.t-mobile.com",
        "fedex.com",
        "*.fedex.com",
        "ups.com",
        "*.ups.com",
        // VPN
        "privateinternetaccess.com",
        "*.privateinternetaccess.com",
        // Microsoft / Xbox / Windows
        "microsoft.com",
        "*.microsoft.com",
        "microsoftonline.com",
        "*.microsoftonline.com",
        "live.com",
        "*.live.com",
        "xboxlive.com",
        "*.xboxlive.com",
        "xbox.com",
        "*.xbox.com",
        "ctldl.windowsupdate.com",
        "crl.microsoft.com",
        "clientconfig.passport.net",
        // RCS messaging via Google Jibe (Apple and Google Messages clients).
        // The clients certificate-pin, and connections arrive with a
        // parenthesized service selector in the CONNECT authority
        // (`rbm.goog(smsft):443`) that the proxy strips before matching.
        "rbm.goog",
        "*.rbm.goog",
        "telephony.goog",
        "*.telephony.goog",
        "jibe.google.com",
        "*.jibe.google.com",
        "jibemobile.com",
        "*.jibemobile.com",
        "messages.google.com",
        "rcs.telephony.goog",
        "*.rcs.telephony.goog",
        // Google client config (used by Chrome / browser cert pinning)
        "clients1.google.com",
        "clients2.google.com",
        "clients3.google.com",
        "clients4.google.com",
        "clients5.google.com",
        // Steam
        "steam.com",
        "*.steam.com",
        "steamcommunity.com",
        "*.steamcommunity.com",
        "steampowered.com",
        "*.steampowered.com",
        "steamcontent.com",
        "*.steamcontent.com",
        "steamstatic.com",
        "*.steamstatic.com",
        "steamserver.net",
        "*.steamserver.net",
        // Media / audio
        "tidal.com",
        "*.tidal.com",
        "soundcloud.com",
        "*.soundcloud.com",
        "smsl-audio.com",
        "*.smsl-audio.com",
        "sourceforge.net",
        "*.sourceforge.net",
        // Cloudflare-fronted strict TLS endpoints
        "cdnjs.cloudflare.com",
        "challenges.cloudflare.com",
        // Certificate authorities
        "digicert.com",
        "*.digicert.com",
        "verisign.com",
        "*.verisign.com",
        // GitHub
        "github.com",
        "*.github.com",
        "githubassets.com",
        "*.githubassets.com",
        // Misc cert-pinned hosts
        "uber.com",
        "*.uber.com",
        "bitcoingold.org",
        "*.bitcoingold.org",
        "btcgpu.org",
        "*.btcgpu.org",
        "newsedge.net",
        "*.newsedge.net",
    ]
}

/// One atomic snapshot keeps the mode and both lists consistent for a request.
#[derive(Debug, Clone)]
struct InterceptionRules {
    exclusions: WildMatchCollection,
    inclusions: WildMatchCollection,
    include_only: bool,
}

impl From<&crate::configuration::Configuration> for InterceptionRules {
    fn from(configuration: &crate::configuration::Configuration) -> Self {
        Self {
            exclusions: WildMatchCollection::new(
                configuration.exclusions.iter().cloned().collect(),
            ),
            inclusions: WildMatchCollection::new(
                configuration.inclusions.iter().cloned().collect(),
            ),
            include_only: configuration.include_only,
        }
    }
}

#[derive(Debug, Clone)]
pub struct LocalExclusionStore(Arc<RwLock<InterceptionRules>>);

impl LocalExclusionStore {
    #[cfg(test)]
    pub fn new(exclusions: Vec<String>) -> Self {
        Self(Arc::new(RwLock::new(InterceptionRules {
            exclusions: WildMatchCollection::new(exclusions),
            inclusions: WildMatchCollection::new(Vec::new()),
            include_only: false,
        })))
    }

    pub fn from_configuration(configuration: &crate::configuration::Configuration) -> Self {
        Self(Arc::new(RwLock::new(configuration.into())))
    }

    pub fn replace_configuration(&self, configuration: &crate::configuration::Configuration) {
        *self.0.write().unwrap() = configuration.into();
    }

    /// Match both forms of a CONNECT hostname (e.g. rbm.goog(smsft) and
    /// rbm.goog) before applying the mode. Negating each match independently
    /// would incorrectly bypass a host whose inclusion matches just one form.
    pub fn should_intercept(&self, host: &str, raw_host: &str) -> bool {
        let rules = self.0.read().unwrap();
        let matches = |list: &WildMatchCollection| {
            list.is_match(host) || (raw_host != host && list.is_match(raw_host))
        };
        !matches(&DEFAULT_EXCLUSIONS)
            && !matches(&rules.exclusions)
            && (!rules.include_only || matches(&rules.inclusions))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(include_only: bool, inclusions: &[&str], exclusions: &[&str]) -> LocalExclusionStore {
        LocalExclusionStore(Arc::new(RwLock::new(InterceptionRules {
            include_only,
            inclusions: WildMatchCollection::new(
                inclusions.iter().map(|s| s.to_string()).collect(),
            ),
            exclusions: WildMatchCollection::new(
                exclusions.iter().map(|s| s.to_string()).collect(),
            ),
        })))
    }

    #[test]
    fn normal_mode_preserves_exclusions_and_ignores_inclusions() {
        let store = policy(false, &["included.test"], &["excluded.test"]);
        assert!(store.should_intercept("other.test", "other.test"));
        assert!(!store.should_intercept("excluded.test", "excluded.test"));
        assert!(!store.should_intercept("setup.icloud.com", "setup.icloud.com"));
    }

    #[test]
    fn inclusion_mode_matches_exact_and_wildcard_hosts_case_insensitively() {
        let store = policy(
            true,
            &["EXAMPLE.com", "*.example.net", "192.0.2.*", "[::1]"],
            &[],
        );
        for host in ["example.com", "Sub.Example.NET", "192.0.2.42", "[::1]"] {
            assert!(store.should_intercept(host, host), "{host}");
        }
        for host in [
            "sub.example.com",
            "example.net",
            "example.com.evil.test",
            "other.test",
        ] {
            assert!(!store.should_intercept(host, host), "{host}");
        }
        assert!(!policy(true, &[], &[]).should_intercept("example.com", "example.com"));
    }

    #[test]
    fn exclusions_always_win_even_when_everything_is_included() {
        let store = policy(true, &["*"], &["*.example.com"]);
        assert!(store.should_intercept("other.test", "other.test"));
        assert!(!store.should_intercept("sub.example.com", "sub.example.com"));
        assert!(!store.should_intercept("setup.icloud.com", "setup.icloud.com"));
    }

    #[test]
    fn service_selector_aliases_are_matched_before_applying_the_mode() {
        for included in ["rbm.goog", "rbm.goog(smsft)"] {
            let store = policy(true, &[included], &[]);
            assert!(store.should_intercept("rbm.goog", "rbm.goog(smsft)"));
            for excluded in ["rbm.goog", "rbm.goog(smsft)"] {
                assert!(!policy(true, &[included], &[excluded])
                    .should_intercept("rbm.goog", "rbm.goog(smsft)"));
            }
        }
    }
}
