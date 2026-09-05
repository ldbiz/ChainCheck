//! Campaign content IOC classification and payload content-signal counting.

use std::sync::LazyLock;

use regex::Regex;

use super::intelligence::{
    CAMPAIGN_MARKER, EXFIL_DOMAIN, NODEREAL_CONTRACT, NODEREAL_DOMAIN, WEAK_IOCS,
};

const CONTENT_SIGNAL_PATTERNS: &[&str] = &[
    r"Math_Symbol\.js",
    r"math_init\.js",
    r"execFileSync",
    r"npm-cache\.com",
    r"registry\.npmjs\.org/-/whoami",
    r"ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    r"Shai-Hulud",
    r"bun-v1\.3\.13",
];

static CONTENT_SIGNALS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    CONTENT_SIGNAL_PATTERNS
        .iter()
        .map(|p| Regex::new(p).expect("CONTENT_SIGNALS"))
        .collect()
});

/// Return `(high, medium)` campaign/content IOC labels found in arbitrary text.
///
/// The NodeReal hostname is shared infrastructure and is contextual by itself.
/// The published contract address is campaign-specific and therefore strong
/// on its own. Labels use canonical constant casing. First-seen order is kept.
pub fn content_ioc_matches(text: &str) -> (Vec<&'static str>, Vec<&'static str>) {
    let lowered = text.to_lowercase();
    let mut high: Vec<&'static str> = Vec::new();
    let mut medium: Vec<&'static str> = Vec::new();
    if lowered.contains(EXFIL_DOMAIN) {
        high.push(EXFIL_DOMAIN);
    }
    if lowered.contains(&CAMPAIGN_MARKER.to_lowercase()) {
        high.push(CAMPAIGN_MARKER);
    }
    let has_node = lowered.contains(NODEREAL_DOMAIN);
    let has_contract = lowered.contains(&NODEREAL_CONTRACT.to_lowercase());
    if has_contract {
        high.push(NODEREAL_CONTRACT);
        if has_node {
            high.push(NODEREAL_DOMAIN);
        }
    } else if has_node {
        medium.push(NODEREAL_DOMAIN);
    }
    for value in WEAK_IOCS {
        if lowered.contains(&value.to_lowercase()) {
            medium.push(*value);
        }
    }
    (dedup_first_seen(high), dedup_first_seen(medium))
}

fn dedup_first_seen(labels: Vec<&'static str>) -> Vec<&'static str> {
    let mut out = Vec::new();
    for label in labels {
        if !out.contains(&label) {
            out.push(label);
        }
    }
    out
}

/// Count of distinct payload content-signal patterns that match `text`.
pub fn content_signal_count(text: &str) -> usize {
    CONTENT_SIGNALS
        .iter()
        .filter(|re| re.is_match(text))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nodereal_alone_is_medium() {
        let (high, medium) = content_ioc_matches("eth-mainnet.nodereal.io");
        assert!(high.is_empty());
        assert_eq!(medium, ["eth-mainnet.nodereal.io"]);
    }

    #[test]
    fn contract_alone_is_high() {
        let (high, medium) = content_ioc_matches("0xE1f2395ee43e45A1556EC6438a88c31B83493103");
        assert_eq!(high, ["0xE1f2395ee43e45A1556EC6438a88c31B83493103"]);
        assert!(medium.is_empty());
    }

    #[test]
    fn nodereal_plus_contract_both_high() {
        let (high, medium) = content_ioc_matches(
            "https://eth-mainnet.nodereal.io/v3/0xE1f2395ee43e45A1556EC6438a88c31B83493103",
        );
        assert_eq!(
            high,
            [
                "0xE1f2395ee43e45A1556EC6438a88c31B83493103",
                "eth-mainnet.nodereal.io"
            ]
        );
        assert!(medium.is_empty());
    }

    #[test]
    fn marker_and_exfil_are_high_weak_still_medium() {
        let (high, medium) =
            content_ioc_matches("Shai-Hulud: Here We Go Again npm-cache.com setup.mjs bun-v1.3.13");
        assert_eq!(high, ["npm-cache.com", "Shai-Hulud: Here We Go Again"]);
        assert_eq!(medium, ["setup.mjs", "bun-v1.3.13"]);
    }

    #[test]
    fn content_signals_count_distinct_patterns() {
        let text =
            "execFileSync(bun, ['Math_Symbol.js']);\nfetch('https://npm-cache.com/router');\n";
        assert_eq!(content_signal_count(text), 3);
    }
}
