//! uBO conditional directives and source permissions, before adblock-rust parsing.
use adblock::resources::PermissionMask;
use url::Url;

/// Also used by build-scriptlets.mjs for upstream `requiresTrust` resources.
pub(crate) const TRUSTED_SCRIPTLETS: PermissionMask = PermissionMask::from_bits(1);

pub(crate) struct FilterList {
    pub name: String,
    pub contents: String,
    pub trusted: bool,
}

/// Only the official uBO filter repositories have automatic scriptlet trust.
/// In particular, neither a lookalike host nor arbitrary GitHub lists qualify.
pub(crate) fn is_trusted_source(url: &Url) -> bool {
    url.scheme() == "https"
        && url.host_str() == Some("raw.githubusercontent.com")
        && url.port().is_none()
        && url.username().is_empty()
        && url.password().is_none()
        && [
            "/uBlockOrigin/uAssets/master/filters/",
            "/uBlockOrigin/uAssets/refs/heads/master/filters/",
            "/uBlockOrigin/uAssetsCDN/main/filters/",
        ]
        .iter()
        .any(|prefix| {
            url.path().strip_prefix(prefix).is_some_and(|name| {
                name.ends_with(".txt")
                    && name.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
                    })
            })
        })
}

/// A portable uBO syntax profile. A shared proxy cannot assume its clients use
/// Firefox, Chromium, or a mobile browser. HTML rewriting for injection does not
/// implement uBO HTML filtering/$replace or $ipaddress, so those capabilities
/// must remain false and lists can select their scriptlet fallbacks instead.
fn token_value(token: &str) -> Option<bool> {
    let (negated, token) = match token.strip_prefix('!') {
        Some(token) => (true, token),
        None => (false, token),
    };
    let value = match token {
        "ext_ublock" => true,
        "false"
        | "ext_ubol"
        | "ext_devbuild"
        | "ext_abp"
        | "adguard"
        | "env_brave"
        | "env_chromium"
        | "env_edge"
        | "env_firefox"
        | "env_legacy"
        | "env_mobile"
        | "env_mv3"
        | "env_safari"
        | "adguard_app_android"
        | "adguard_app_cli"
        | "adguard_app_ios"
        | "adguard_app_mac"
        | "adguard_app_windows"
        | "adguard_ext_android_cb"
        | "adguard_ext_chromium"
        | "adguard_ext_chromium_mv3"
        | "adguard_ext_edge"
        | "adguard_ext_firefox"
        | "adguard_ext_opera"
        | "adguard_ext_safari" => false,
        token if token.starts_with("cap_") => false,
        _ => return None,
    };
    Some(value != negated)
}

// uBO evaluates a chain from left to right, with optional outer parentheses.
// Unrecognized expressions remain unknown, as in uBO: neither branch is removed.
fn evaluate_condition(expression: &str) -> Option<bool> {
    let expression = expression.trim();
    let expression = expression
        .strip_prefix('(')
        .and_then(|inner| inner.strip_suffix(')'))
        .unwrap_or(expression);
    let mut tokens = expression.split_whitespace();
    let mut result = token_value(tokens.next()?)?;
    while let Some(operator) = tokens.next() {
        let rhs = token_value(tokens.next()?)?;
        result = match operator {
            "&&" => result && rhs,
            "||" => result || rhs,
            _ => return None,
        };
    }
    Some(result)
}

struct Conditional {
    parent_active: bool,
    condition: Option<bool>,
    in_else: bool,
}

pub(crate) struct Preprocessed<'a> {
    pub lines: Vec<&'a str>,
    pub unknown_conditions: usize,
    /// Zero-based source line and relative path, in source order.
    pub includes: Vec<(usize, &'a str)>,
}

/// Keep directive scope local to each list. Reject malformed structure instead
/// of letting an unmatched directive accidentally disable the rest of a list.
pub(crate) fn preprocess(contents: &str) -> Result<Preprocessed<'_>, String> {
    preprocess_inner(contents, false)
}

/// Find active includes without losing the original conditional blocks. Each
/// downloaded fragment is checked separately so it cannot close a parent's if.
pub(crate) fn preprocess_for_download(contents: &str) -> Result<Preprocessed<'_>, String> {
    preprocess_inner(contents, true)
}

fn preprocess_inner(contents: &str, allow_includes: bool) -> Result<Preprocessed<'_>, String> {
    let mut result = Preprocessed {
        lines: Vec::new(),
        unknown_conditions: 0,
        includes: Vec::new(),
    };
    let mut stack: Vec<Conditional> = Vec::new();
    let mut active = true;
    for (index, line) in contents.lines().enumerate() {
        let line = line.trim().trim_start_matches('\u{feff}');
        let (directive, argument) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
        let error = |message| format!("line {}: {message}", index + 1);
        match directive {
            "!#if" => {
                if argument.trim().is_empty() {
                    return Err(error("missing condition"));
                }
                if stack.len() >= 128 {
                    return Err(error("conditional nesting exceeds 128 levels"));
                }
                let condition = evaluate_condition(argument);
                if condition.is_none() {
                    result.unknown_conditions += 1;
                }
                stack.push(Conditional {
                    parent_active: active,
                    condition,
                    in_else: false,
                });
                active &= condition.unwrap_or(true);
            }
            "!#else" => {
                let frame = stack.last_mut().ok_or_else(|| error("unmatched !#else"))?;
                if frame.in_else {
                    return Err(error("duplicate !#else"));
                }
                frame.in_else = true;
                active = frame.parent_active && frame.condition.map(|value| !value).unwrap_or(true);
            }
            "!#endif" => {
                let frame = stack.pop().ok_or_else(|| error("unmatched !#endif"))?;
                active = frame.parent_active;
            }
            "!#include" if active => {
                if !allow_includes {
                    return Err(error(
                        "unresolved !#include; refresh the subscription to download its sub-lists",
                    ));
                }
                let path = argument
                    .split_whitespace()
                    .next()
                    .ok_or_else(|| error("missing !#include path"))?;
                result.includes.push((index, path));
            }
            _ if active => result.lines.push(line),
            _ => {}
        }
    }
    if !stack.is_empty() {
        return Err("unterminated !#if".to_owned());
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_conditions_select_portable_scriptlet_fallbacks() {
        let input = "!#if cap_html_filtering\nreplace-rule\n!#else\nscriptlet-rule\n!#if env_firefox\nfirefox-only\n!#else\nportable\n!#endif\n!#endif\nafter";
        assert_eq!(
            preprocess(input).unwrap().lines,
            ["scriptlet-rule", "portable", "after"]
        );
        let input =
            "!#if false\n!#if !false\nhidden\n!#else\nalso-hidden\n!#endif\n!#endif\nvisible";
        assert_eq!(preprocess(input).unwrap().lines, ["visible"]);
    }

    #[test]
    fn conditions_follow_ubo_left_to_right_boolean_chains() {
        assert_eq!(
            evaluate_condition("(!ext_ubol && !cap_html_filtering)"),
            Some(true)
        );
        assert_eq!(evaluate_condition("!false || false && false"), Some(false));
        assert_eq!(evaluate_condition("cap_future_feature"), Some(false));
        assert_eq!(evaluate_condition("adguard_future_platform"), None);
        assert_eq!(evaluate_condition("!cap_future_feature"), Some(true));
        assert_eq!(
            evaluate_condition("env_firefox || env_chromium"),
            Some(false)
        );
    }

    #[test]
    fn unknown_conditions_preserve_both_branches_like_ubo() {
        let parsed = preprocess("!#if future_token\na\n!#else\nb\n!#endif").unwrap();
        assert_eq!(parsed.lines, ["a", "b"]);
        assert_eq!(parsed.unknown_conditions, 1);
    }

    #[test]
    fn only_active_includes_are_downloaded_and_keep_source_positions() {
        let input = "!#if false\n!#include ignored.txt\n!#else\n!#include first.txt comment\n!#endif\n!#if future_token\n!#include second.txt\n!#else\n!#include third.txt\n!#endif";
        let parsed = preprocess_for_download(input).unwrap();
        assert_eq!(
            parsed.includes,
            [(3, "first.txt"), (6, "second.txt"), (8, "third.txt")]
        );
        assert_eq!(parsed.unknown_conditions, 1);
        assert!(preprocess_for_download("!#include").is_err());
        assert!(preprocess_for_download("!#if false\n!#include\n!#endif").is_ok());
    }

    #[test]
    fn malformed_directives_and_active_includes_fail() {
        for input in [
            "!#else",
            "!#endif",
            "!#if",
            "!#if false",
            "!#if false\n!#else\n!#else\n!#endif",
            "!#include more.txt",
        ] {
            assert!(preprocess(input).is_err(), "{input}");
        }
        assert!(preprocess("!#if false\n!#include unused.txt\n!#endif").is_ok());
        assert!(preprocess(&"!#if !false\n".repeat(129)).is_err());
        assert_eq!(
            preprocess("\u{feff}!#if !false\r\na\r\n!#endif\r\n")
                .unwrap()
                .lines,
            ["a"]
        );
    }

    #[test]
    fn scriptlet_trust_is_limited_to_official_sources() {
        for url in [
            "https://raw.githubusercontent.com/uBlockOrigin/uAssetsCDN/main/filters/filters.min.txt",
            "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters-mobile.txt",
        ] {
            assert!(is_trusted_source(&Url::parse(url).unwrap()));
        }
        for url in [
            "http://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt",
            "https://raw.githubusercontent.com.evil.test/uBlockOrigin/uAssets/master/filters/filters.txt",
            "https://raw.githubusercontent.com/another/repo/main/filters/filters.txt",
            "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/../other.txt",
            "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/..%2F..%2Fother.txt",
            "https://raw.githubusercontent.com:8443/uBlockOrigin/uAssets/master/filters/filters.txt",
        ] {
            assert!(!is_trusted_source(&Url::parse(url).unwrap()));
        }
    }
}
