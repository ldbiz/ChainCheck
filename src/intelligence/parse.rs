//! Malware feed JSON parsing.

use serde_json::Value;

use crate::model::{Ecosystem, PackageIdentity, PackageKey, PackageVersion};

use super::{AvailableFeed, FeedFailure, IntelligenceProvenance, MalwareIndex};

fn usable_string(value: Option<&Value>) -> Option<&str> {
    match value {
        Some(Value::String(text)) if !text.is_empty() => Some(text),
        _ => None,
    }
}

/// Parse a generic malware feed body. `etag` is unset; the fetch layer fills it.
pub fn parse_malware_feed(
    bytes: &[u8],
    ecosystem: Ecosystem,
) -> Result<AvailableFeed, FeedFailure> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| FeedFailure::InvalidJson)?;
    parse_malware_feed_value(&value, ecosystem)
}

pub(crate) fn parse_malware_feed_value(
    value: &Value,
    ecosystem: Ecosystem,
) -> Result<AvailableFeed, FeedFailure> {
    let Value::Array(items) = value else {
        return Err(FeedFailure::InvalidTopLevel);
    };

    let mut index = MalwareIndex::new(ecosystem);
    let mut accepted_records = 0usize;
    let mut rejected_malformed = 0usize;
    let mut rejected_non_malware = 0usize;

    for item in items {
        let Some(object) = item.as_object() else {
            rejected_malformed += 1;
            continue;
        };
        let Some(package_name) = usable_string(object.get("package_name")) else {
            rejected_malformed += 1;
            continue;
        };
        let Some(version) = usable_string(object.get("version")) else {
            rejected_malformed += 1;
            continue;
        };
        let Some(reason) = usable_string(object.get("reason")) else {
            rejected_malformed += 1;
            continue;
        };
        if !reason.eq_ignore_ascii_case("MALWARE") {
            rejected_non_malware += 1;
            continue;
        }

        let identity = PackageIdentity::new(ecosystem, package_name);
        if version == "*" {
            index.wildcard.insert(identity);
        } else {
            index
                .exact
                .insert(PackageKey::new(identity, PackageVersion::exact(version)));
        }
        accepted_records += 1;
    }

    if accepted_records == 0 {
        return Err(FeedFailure::NoValidMalwareRecords);
    }

    Ok(AvailableFeed {
        index,
        accepted_records,
        rejected_malformed,
        rejected_non_malware,
        etag: None,
        provenance: IntelligenceProvenance::Live,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intelligence::MalwareMatch;
    use crate::model::Ecosystem;

    const VALID_NPM: &str = include_str!("../../tests/fixtures/feeds/valid-npm.json");
    const VALID_PYPI: &str = include_str!("../../tests/fixtures/feeds/valid-pypi.json");
    const FILTER_TELEMETRY: &str = include_str!("../../tests/fixtures/feeds/filter-telemetry.json");
    const FILTER_PROTESTWARE: &str =
        include_str!("../../tests/fixtures/feeds/filter-protestware.json");
    const FILTER_OTHER: &str = include_str!("../../tests/fixtures/feeds/filter-other-reason.json");
    const MIXED: &str = include_str!("../../tests/fixtures/feeds/mixed-malformed-and-valid.json");
    const INVALID_JSON: &str = include_str!("../../tests/fixtures/feeds/invalid-json.txt");
    const WRONG_TOP: &str = include_str!("../../tests/fixtures/feeds/wrong-toplevel-object.json");
    const EMPTY: &str = include_str!("../../tests/fixtures/feeds/empty-array.json");
    const ONLY_NON: &str = include_str!("../../tests/fixtures/feeds/only-non-malware.json");
    const ONLY_MALFORMED: &str = include_str!("../../tests/fixtures/feeds/only-malformed.json");

    #[test]
    fn valid_npm_feed_indexes_exact_wildcard_mixed_case_and_extra_fields() {
        let feed = parse_malware_feed(VALID_NPM.as_bytes(), Ecosystem::Npm).unwrap();
        assert_eq!(feed.accepted_records(), 4);
        let index = feed.index();
        assert_eq!(
            index.matches(
                &PackageIdentity::npm("exact-malware"),
                Some(&PackageVersion::exact("1.2.3")),
            ),
            Some(MalwareMatch::Exact)
        );
        assert_eq!(
            index.matches(&PackageIdentity::npm("wildcard-malware"), None),
            Some(MalwareMatch::Wildcard)
        );
        assert_eq!(
            index.matches(
                &PackageIdentity::npm("wildcard-malware"),
                Some(&PackageVersion::exact("99.0.0")),
            ),
            Some(MalwareMatch::Wildcard)
        );
        assert_eq!(
            index.matches(
                &PackageIdentity::npm("mixed-case-reason"),
                Some(&PackageVersion::exact("0.1.0")),
            ),
            Some(MalwareMatch::Exact)
        );
        assert_eq!(
            index.matches(
                &PackageIdentity::npm("extra-fields"),
                Some(&PackageVersion::exact("9.9.9")),
            ),
            Some(MalwareMatch::Exact)
        );
        assert!(
            index
                .wildcard
                .contains(&PackageIdentity::npm("wildcard-malware"))
        );
        assert!(!index.exact.iter().any(|key| key.version.as_str() == "*"));
    }

    #[test]
    fn valid_pypi_feed_canonicalises_names() {
        let feed = parse_malware_feed(VALID_PYPI.as_bytes(), Ecosystem::Pypi).unwrap();
        let index = feed.index();
        assert_eq!(
            index.matches(
                &PackageIdentity::pypi("exact-malware"),
                Some(&PackageVersion::exact("1.2.3")),
            ),
            Some(MalwareMatch::Exact)
        );
        assert_eq!(
            index.matches(
                &PackageIdentity::pypi("Exact_Malware"),
                Some(&PackageVersion::exact("1.2.3")),
            ),
            Some(MalwareMatch::Exact)
        );
        assert_eq!(
            index.matches(&PackageIdentity::pypi("wildcard-malware"), None),
            Some(MalwareMatch::Wildcard)
        );
        assert_eq!(
            index.matches(
                &PackageIdentity::pypi("extra-fields-pkg"),
                Some(&PackageVersion::exact("9.9.9")),
            ),
            Some(MalwareMatch::Exact)
        );
    }

    #[test]
    fn telemetry_protestware_and_other_reasons_are_not_malware() {
        assert_eq!(
            parse_malware_feed(FILTER_TELEMETRY.as_bytes(), Ecosystem::Npm),
            Err(FeedFailure::NoValidMalwareRecords)
        );
        assert_eq!(
            parse_malware_feed(FILTER_PROTESTWARE.as_bytes(), Ecosystem::Npm),
            Err(FeedFailure::NoValidMalwareRecords)
        );
        assert_eq!(
            parse_malware_feed(FILTER_OTHER.as_bytes(), Ecosystem::Npm),
            Err(FeedFailure::NoValidMalwareRecords)
        );
    }

    #[test]
    fn mixed_malformed_and_valid_remains_available() {
        let feed = parse_malware_feed(MIXED.as_bytes(), Ecosystem::Npm).unwrap();
        assert_eq!(feed.accepted_records(), 2);
        assert!(feed.rejected_malformed() >= 5);
        assert_eq!(
            feed.index().matches(
                &PackageIdentity::npm("good-one"),
                Some(&PackageVersion::exact("1.0.0")),
            ),
            Some(MalwareMatch::Exact)
        );
        assert_eq!(
            feed.index().matches(
                &PackageIdentity::npm("good-two"),
                Some(&PackageVersion::exact("2.0.0")),
            ),
            Some(MalwareMatch::Exact)
        );
    }

    #[test]
    fn invalid_feeds_are_typed_failures() {
        assert_eq!(
            parse_malware_feed(INVALID_JSON.as_bytes(), Ecosystem::Npm),
            Err(FeedFailure::InvalidJson)
        );
        assert_eq!(
            parse_malware_feed(WRONG_TOP.as_bytes(), Ecosystem::Npm),
            Err(FeedFailure::InvalidTopLevel)
        );
        assert_eq!(
            parse_malware_feed(b"null", Ecosystem::Npm),
            Err(FeedFailure::InvalidTopLevel)
        );
        assert_eq!(
            parse_malware_feed(EMPTY.as_bytes(), Ecosystem::Npm),
            Err(FeedFailure::NoValidMalwareRecords)
        );
        assert_eq!(
            parse_malware_feed(ONLY_NON.as_bytes(), Ecosystem::Npm),
            Err(FeedFailure::NoValidMalwareRecords)
        );
        assert_eq!(
            parse_malware_feed(ONLY_MALFORMED.as_bytes(), Ecosystem::Npm),
            Err(FeedFailure::NoValidMalwareRecords)
        );
    }

    #[test]
    fn exact_match_preferred_over_wildcard() {
        let json = br#"[
            {"package_name":"both","version":"1.0.0","reason":"MALWARE"},
            {"package_name":"both","version":"*","reason":"MALWARE"}
        ]"#;
        let feed = parse_malware_feed(json, Ecosystem::Npm).unwrap();
        assert_eq!(
            feed.index().matches(
                &PackageIdentity::npm("both"),
                Some(&PackageVersion::exact("1.0.0")),
            ),
            Some(MalwareMatch::Exact)
        );
        assert_eq!(
            feed.index().matches(
                &PackageIdentity::npm("both"),
                Some(&PackageVersion::exact("2.0.0")),
            ),
            Some(MalwareMatch::Wildcard)
        );
    }

    #[test]
    fn versions_are_opaque_and_ecosystems_do_not_cross_match() {
        let npm = parse_malware_feed(VALID_NPM.as_bytes(), Ecosystem::Npm).unwrap();
        assert_eq!(
            npm.index().matches(
                &PackageIdentity::npm("exact-malware"),
                Some(&PackageVersion::exact("1.2.3+meta")),
            ),
            None
        );
        assert_eq!(
            npm.index().matches(
                &PackageIdentity::pypi("exact-malware"),
                Some(&PackageVersion::exact("1.2.3")),
            ),
            None
        );
        let pypi = parse_malware_feed(VALID_PYPI.as_bytes(), Ecosystem::Pypi).unwrap();
        assert_eq!(
            pypi.index().matches(
                &PackageIdentity::npm("exact-malware"),
                Some(&PackageVersion::exact("1.2.3")),
            ),
            None
        );
    }
}
