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

lazy_static! {
    static ref DEFAULT_EXCLUSIONS: WildMatchCollection = {
        let mut exclusions = Vec::new();

        // Apple service exclusions, as defined in : https://support.apple.com/en-us/HT210060
        // > Apple services will fail any connection that uses
        // > HTTPS Interception (SSL Inspection). If the HTTPS traffic
        // > traverses a web proxy, disable HTTPS Interception for the hosts
        // > listed in this article.
        exclusions.push(String::from("*.apple.com"));
        exclusions.push(String::from("static.ips.apple.com"));
        exclusions.push(String::from("*.push.apple.com"));
        exclusions.push(String::from("setup.icloud.com"));
        exclusions.push(String::from("*.business.apple.com"));
        exclusions.push(String::from("*.school.apple.com"));
        exclusions.push(String::from("upload.appleschoolcontent.com"));
        exclusions.push(String::from("ws-ee-maidsvc.icloud.com"));
        exclusions.push(String::from("itunes.com"));
        exclusions.push(String::from("appldnld.apple.com.edgesuite.net"));
        exclusions.push(String::from("*.itunes.apple.com"));
        exclusions.push(String::from("updates-http.cdn-apple.com"));
        exclusions.push(String::from("updates.cdn-apple.com"));
        exclusions.push(String::from("*.apps.apple.com"));
        exclusions.push(String::from("*.mzstatic.com"));
        exclusions.push(String::from("*.appattest.apple.com"));
        exclusions.push(String::from("doh.dns.apple.com"));
        exclusions.push(String::from("appleid.cdn-apple.com"));
        exclusions.push(String::from("*.apple-cloudkit.com"));
        exclusions.push(String::from("*.apple-livephotoskit.com"));
        exclusions.push(String::from("*.apzones.com"));
        exclusions.push(String::from("*.cdn-apple.com"));
        exclusions.push(String::from("*.gc.apple.com"));
        exclusions.push(String::from("*.icloud.com"));
        exclusions.push(String::from("*.icloud.com.cn"));
        exclusions.push(String::from("*.icloud.apple.com"));
        exclusions.push(String::from("*.icloud-content.com"));
        exclusions.push(String::from("*.iwork.apple.com"));
        exclusions.push(String::from("mask.icloud.com"));
        exclusions.push(String::from("mask-h2.icloud.com"));
        exclusions.push(String::from("mask-api.icloud.com"));
        exclusions.push(String::from("devimages-cdn.apple.com"));
        exclusions.push(String::from("download.developer.apple.com"));

        WildMatchCollection::new(exclusions)
    };
}

/// Hosts the maintainer has observed to use certificate pinning, HSTS preload
/// + strict TLS, or otherwise break under MITM interception. Exposed to the
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

#[derive(Debug, Clone)]
pub struct LocalExclusionStore(Arc<RwLock<WildMatchCollection>>);

impl LocalExclusionStore {
    pub fn new(exclusions: Vec<String>) -> Self {
        let collection = WildMatchCollection::new(exclusions);
        Self(Arc::new(RwLock::new(collection)))
    }

    pub fn replace_exclusions(&mut self, exclusions: Vec<String>) {
        let new_exclusion_store = LocalExclusionStore::new(exclusions);

        *self.0.write().unwrap() = new_exclusion_store.0.read().unwrap().clone();
    }

    pub fn contains(&self, element: &str) -> bool {
        if DEFAULT_EXCLUSIONS.is_match(element) {
            true
        } else {
            self.0.read().unwrap().is_match(element)
        }
    }
}
