//! Bundled ChainDrop/Shai-Hulud campaign intelligence.
//!
//! Fixed indicators derived from documented incident intelligence. They are not
//! remotely updated and require a ChainCheck release when the known set changes.
//! Last reviewed: 2026-08-29 (Aikido Safe Chain incident intelligence).
//!
//! File-level SHA-256 values published by Aikido identify payload files on disk.
//! They are NOT tarball integrity hashes and must not be compared with npm cache
//! content (sha512/sha1 tarball integrity).

use std::collections::HashMap;

/// Git history lower bound for this campaign.
pub const SINCE_GIT: &str = "2026-08-04T00:00:00Z";

pub const EXFIL_DOMAIN: &str = "npm-cache.com";
pub const NODEREAL_DOMAIN: &str = "eth-mainnet.nodereal.io";
pub const NODEREAL_CONTRACT: &str = "0xE1f2395ee43e45A1556EC6438a88c31B83493103";
pub const CAMPAIGN_MARKER: &str = "Shai-Hulud: Here We Go Again";

pub const WORM_EMAIL: &str = "claude@users.noreply.github.com";
pub const WORM_SUBJECT: &str = "chore: update config";

pub const PAYLOAD_NAMES: &[&str] = &["setup.mjs", "Math_Symbol.js", "math_init.js"];

pub const WEAK_IOCS: &[&str] = &["setup.mjs", "Math_Symbol.js", "math_init.js", "bun-v1.3.13"];

const BUNDLED_HASHES: &[(&str, &str)] = &[
    (
        "54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668",
        "setup.mjs (initial)",
    ),
    (
        "fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb",
        "setup.mjs (community spread)",
    ),
    (
        "9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc",
        "Math_Symbol.js / math_init.js payload",
    ),
];

/// Owned campaign intelligence. Clone and inject hashes in tests; never mutate
/// the production [`bundled`](CampaignIntelligence::bundled) value in place.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CampaignIntelligence {
    payload_hashes: HashMap<String, String>,
}

impl CampaignIntelligence {
    pub fn bundled() -> Self {
        let mut payload_hashes = HashMap::new();
        for (digest, label) in BUNDLED_HASHES {
            payload_hashes.insert((*digest).to_owned(), (*label).to_owned());
        }
        Self { payload_hashes }
    }

    pub fn with_injected_payload_hash(
        mut self,
        digest: impl Into<String>,
        label: impl Into<String>,
    ) -> Self {
        self.payload_hashes.insert(digest.into(), label.into());
        self
    }

    pub fn payload_label(&self, digest: &str) -> Option<&str> {
        self.payload_hashes.get(digest).map(String::as_str)
    }
}

pub fn is_payload_name(name: &str) -> bool {
    PAYLOAD_NAMES.contains(&name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_hashes_match_python_oracle() {
        let intel = CampaignIntelligence::bundled();
        assert_eq!(
            intel.payload_label("54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668"),
            Some("setup.mjs (initial)")
        );
        assert_eq!(
            intel.payload_label("fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb"),
            Some("setup.mjs (community spread)")
        );
        assert_eq!(
            intel.payload_label("9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc"),
            Some("Math_Symbol.js / math_init.js payload")
        );
        assert_eq!(
            PAYLOAD_NAMES,
            &["setup.mjs", "Math_Symbol.js", "math_init.js"]
        );
        assert_eq!(SINCE_GIT, "2026-08-04T00:00:00Z");
        assert_eq!(WORM_EMAIL, "claude@users.noreply.github.com");
        assert_eq!(WORM_SUBJECT, "chore: update config");
    }

    #[test]
    fn injected_hash_does_not_mutate_bundled() {
        let bundled = CampaignIntelligence::bundled();
        let injected = bundled
            .clone()
            .with_injected_payload_hash("abc", "oracle injected hash");
        assert_eq!(injected.payload_label("abc"), Some("oracle injected hash"));
        assert!(
            CampaignIntelligence::bundled()
                .payload_label("abc")
                .is_none()
        );
        assert!(bundled.payload_label("abc").is_none());
    }
}
