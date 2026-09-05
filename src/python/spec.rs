//! Narrow PEP 508 requirement extraction for static declaration parsing.

/// Parsed requirement: package identity and optional exact version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedRequirement {
    pub name: String,
    pub exact_version: Option<String>,
}

/// Extract name and exact version from a PEP 508-ish requirement string.
pub fn parse_requirement(spec: &str) -> Option<ParsedRequirement> {
    let spec = spec.trim();
    if spec.is_empty() || spec.starts_with('#') {
        return None;
    }
    if spec.contains("${") {
        return None;
    }

    let (head, _marker) = split_marker(spec);
    let head = head.trim();
    if head.is_empty() {
        return None;
    }

    // VCS / editable / path-only without name
    if head.starts_with("-e")
        || head.starts_with("git+")
        || head.starts_with("hg+")
        || head.starts_with("svn+")
        || head.starts_with("bzr+")
    {
        return egg_name(head);
    }

    if let Some((name, rest)) = split_name_at_url(head) {
        if let Some(req) = parsed_requirement(name, parse_exact_version(Some(rest))) {
            return Some(req);
        }
        return egg_name(head);
    }

    let (name_part, version_part) = split_name_spec(head);
    parsed_requirement(
        name_part,
        parse_exact_version(if version_part.is_empty() {
            None
        } else {
            Some(version_part)
        }),
    )
}

/// Construct a requirement only when the base distribution name is valid.
fn parsed_requirement(name: &str, exact_version: Option<String>) -> Option<ParsedRequirement> {
    let name = base_distribution_name(name);
    if !is_valid_distribution_name(name) {
        return None;
    }
    Some(ParsedRequirement {
        name: name.to_owned(),
        exact_version,
    })
}

/// Trim whitespace and strip a trailing `[extras]` marker before name validation.
pub(crate) fn base_distribution_name(name: &str) -> &str {
    strip_extras(name.trim())
}

/// PEP 508 / PyPA distribution names: ASCII alphanumerics plus `.`, `_`, `-`,
/// beginning and ending with a letter or digit.
pub(crate) fn is_valid_distribution_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    let Some((first, rest)) = bytes.split_first() else {
        return false;
    };
    let last = rest.last().unwrap_or(first);
    first.is_ascii_alphanumeric()
        && last.is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(*b, b'.' | b'_' | b'-'))
}

fn split_marker(spec: &str) -> (&str, Option<&str>) {
    let mut in_quote = None;
    let mut escaped = false;
    for (i, ch) in spec.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' && in_quote.is_some() {
            escaped = true;
            continue;
        }
        if let Some(q) = in_quote {
            if ch == q {
                in_quote = None;
            }
            continue;
        }
        if ch == '"' || ch == '\'' {
            in_quote = Some(ch);
            continue;
        }
        if ch == ';' {
            return (&spec[..i], Some(&spec[i + ch.len_utf8()..]));
        }
    }
    (spec, None)
}

fn split_name_at_url(head: &str) -> Option<(&str, &str)> {
    let at = head.rfind('@')?;
    if at == 0 {
        return None;
    }
    let name = &head[..at];
    let rest = head[at + 1..].trim();
    if rest.starts_with("http://")
        || rest.starts_with("https://")
        || rest.starts_with("file:")
        || rest.starts_with("git+")
        || rest.starts_with("ssh://")
    {
        return Some((name, rest));
    }
    None
}

fn split_name_spec(head: &str) -> (&str, &str) {
    if let Some((name, rest)) = split_name_at_url(head) {
        return (name, rest);
    }
    let head = head.trim();
    let mut in_quote = None;
    let mut bracket_depth = 0usize;
    for (i, ch) in head.char_indices() {
        if let Some(q) = in_quote {
            if ch == q {
                in_quote = None;
            }
            continue;
        }
        if ch == '"' || ch == '\'' {
            in_quote = Some(ch);
            continue;
        }
        if ch == '[' {
            bracket_depth += 1;
            continue;
        }
        if ch == ']' {
            bracket_depth = bracket_depth.saturating_sub(1);
            continue;
        }
        if bracket_depth > 0 {
            continue;
        }
        for op in ["===", "==", ">=", "<=", "!=", "~="] {
            if head[i..].starts_with(op) {
                return (&head[..i], &head[i..]);
            }
        }
        if (ch == '>' || ch == '<' || ch == ',') && i > 0 {
            return (&head[..i], &head[i..]);
        }
    }
    (head, "")
}

fn strip_extras(name: &str) -> &str {
    let name = name.trim();
    if let Some(open) = name.find('[') {
        if name.ends_with(']') {
            return name[..open].trim();
        }
    }
    name
}

fn parse_exact_version(version_part: Option<&str>) -> Option<String> {
    let version_part = version_part?.trim();
    if version_part.is_empty() {
        return None;
    }
    if version_part.contains("://") || version_part.starts_with("file:") {
        return None;
    }
    let version_part = trim_wrapping_parens(version_part);
    if version_part.is_empty() {
        return None;
    }
    if has_specifier_comma(version_part) {
        return None;
    }
    let token = version_part.trim();
    let rest = if let Some(rest) = token.strip_prefix("===") {
        rest
    } else if let Some(rest) = token.strip_prefix("==") {
        rest
    } else {
        return None;
    };
    let version = rest.trim();
    if version.is_empty() || version.contains('*') {
        return None;
    }
    Some(version.to_owned())
}

fn trim_wrapping_parens(spec: &str) -> &str {
    let spec = spec.trim();
    if spec.starts_with('(') && spec.ends_with(')') && spec.len() >= 2 {
        spec[1..spec.len() - 1].trim()
    } else {
        spec
    }
}

fn has_specifier_comma(spec: &str) -> bool {
    let mut in_quote = None;
    for ch in spec.chars() {
        if let Some(q) = in_quote {
            if ch == q {
                in_quote = None;
            }
            continue;
        }
        if ch == '"' || ch == '\'' {
            in_quote = Some(ch);
            continue;
        }
        if ch == ',' {
            return true;
        }
    }
    false
}

fn egg_name(head: &str) -> Option<ParsedRequirement> {
    for part in head.split('#') {
        if let Some(egg) = part.strip_prefix("egg=") {
            let name = egg.split('&').next()?.trim();
            if let Some(req) = parsed_requirement(name, None) {
                return Some(req);
            }
        }
    }
    None
}

/// Shared conversion for Pipfile string specs and table `version` fields.
pub fn parse_pipfile_version(name: &str, version: &str) -> Option<ParsedRequirement> {
    let name = name.trim();
    let version = version.trim();
    if name.is_empty() || version.is_empty() {
        return None;
    }
    if version == "*" {
        return parsed_requirement(name, None);
    }
    let combined = if is_pipfile_specifier(version) {
        format!("{name}{version}")
    } else {
        format!("{name}=={version}")
    };
    parse_requirement(&combined)
}

fn is_pipfile_specifier(version: &str) -> bool {
    version.starts_with("==")
        || version.starts_with(">=")
        || version.starts_with("<=")
        || version.starts_with("!=")
        || version.starts_with("~=")
        || version.starts_with('>')
        || version.starts_with('<')
}

fn is_poetry_unresolved_version(version: &str) -> bool {
    version.starts_with('^')
        || version.starts_with('~')
        || version.starts_with("~=")
        || version.contains('*')
        || version.contains(',')
        || version.starts_with('<')
        || version.starts_with('>')
        || version.starts_with("!=")
}

fn is_bare_poetry_version(version: &str) -> bool {
    version.chars().next().is_some_and(|c| c.is_ascii_digit())
        && !is_poetry_unresolved_version(version)
}

/// Shared conversion for Poetry string specs and table `version` fields.
pub fn parse_poetry_version(name: &str, version: &str) -> Option<ParsedRequirement> {
    let name = name.trim();
    let version = version.trim();
    if name.is_empty() || version.is_empty() {
        return None;
    }
    if version == "*" || is_poetry_unresolved_version(version) {
        return parsed_requirement(name, None);
    }
    let combined = if version.starts_with("==") || version.starts_with("===") {
        format!("{name}{version}")
    } else if is_bare_poetry_version(version) {
        format!("{name}=={version}")
    } else if is_pipfile_specifier(version) {
        format!("{name}{version}")
    } else {
        return parsed_requirement(name, None);
    };
    parse_requirement(&combined)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_double_equals() {
        let req = parse_requirement("requests==2.28.1").unwrap();
        assert_eq!(req.name, "requests");
        assert_eq!(req.exact_version.as_deref(), Some("2.28.1"));
    }

    #[test]
    fn exact_triple_equals() {
        let req = parse_requirement("requests===2.28.1").unwrap();
        assert_eq!(req.exact_version.as_deref(), Some("2.28.1"));
    }

    #[test]
    fn range_is_name_only() {
        let req = parse_requirement("requests>=2.0,<3").unwrap();
        assert_eq!(req.name, "requests");
        assert!(req.exact_version.is_none());
    }

    #[test]
    fn extras_do_not_change_name() {
        let req = parse_requirement("requests[security]==2.28.1").unwrap();
        assert_eq!(req.name, "requests");
        assert_eq!(req.exact_version.as_deref(), Some("2.28.1"));
    }

    #[test]
    fn extras_with_unresolved_specifier_keep_base_name() {
        let req = parse_requirement("evil-pkg[security] >= 1").unwrap();
        assert_eq!(req.name, "evil-pkg");
        assert!(req.exact_version.is_none());
    }

    #[test]
    fn extras_on_direct_reference_keep_base_name() {
        let req = parse_requirement("evil-pkg[security] @ https://example.com/pkg.tar.gz").unwrap();
        assert_eq!(req.name, "evil-pkg");
        assert!(req.exact_version.is_none());
    }

    #[test]
    fn marker_does_not_require_evaluation() {
        let req = parse_requirement("importlib-metadata; python_version < \"3.8\"").unwrap();
        assert_eq!(req.name, "importlib-metadata");
        assert!(req.exact_version.is_none());
    }

    #[test]
    fn url_reference_is_name_only() {
        let req = parse_requirement("pkg @ https://example.com/pkg-1.0.tar.gz").unwrap();
        assert_eq!(req.name, "pkg");
        assert!(req.exact_version.is_none());
    }

    #[test]
    fn env_var_line_is_skipped() {
        assert!(parse_requirement("${HOME}/pkg").is_none());
    }

    #[test]
    fn wildcard_exact_is_name_only() {
        let req = parse_requirement("pkg==1.*").unwrap();
        assert_eq!(req.name, "pkg");
        assert!(req.exact_version.is_none());
    }

    #[test]
    fn mixed_exact_and_exclusion_is_name_only() {
        let req = parse_requirement("pkg==1.2.3,!=1.2.4").unwrap();
        assert_eq!(req.name, "pkg");
        assert!(req.exact_version.is_none());
    }

    #[test]
    fn mixed_range_and_exact_is_name_only() {
        let req = parse_requirement("pkg>=1,==2").unwrap();
        assert_eq!(req.name, "pkg");
        assert!(req.exact_version.is_none());
    }

    #[test]
    fn range_pair_is_name_only() {
        let req = parse_requirement("pkg>=1,<3").unwrap();
        assert_eq!(req.name, "pkg");
        assert!(req.exact_version.is_none());
    }

    #[test]
    fn pipfile_star_is_name_only() {
        let req = parse_pipfile_version("evil", "*").unwrap();
        assert_eq!(req.name, "evil");
        assert!(req.exact_version.is_none());
    }

    #[test]
    fn pipfile_star_does_not_append_to_name() {
        let req = parse_pipfile_version("evil", "*").unwrap();
        assert_ne!(req.name, "evil*");
    }

    #[test]
    fn pipfile_exact_operator_is_exact() {
        let req = parse_pipfile_version("evil", "==1.0.0").unwrap();
        assert_eq!(req.name, "evil");
        assert_eq!(req.exact_version.as_deref(), Some("1.0.0"));
    }

    #[test]
    fn pipfile_range_is_name_only() {
        let req = parse_pipfile_version("evil", ">=1").unwrap();
        assert_eq!(req.name, "evil");
        assert!(req.exact_version.is_none());
    }

    #[test]
    fn poetry_caret_is_unresolved() {
        let req = parse_poetry_version("evil", "^1.0.0").unwrap();
        assert_eq!(req.name, "evil");
        assert!(req.exact_version.is_none());
    }

    #[test]
    fn poetry_bare_is_exact() {
        let req = parse_poetry_version("evil", "1.0.0").unwrap();
        assert_eq!(req.exact_version.as_deref(), Some("1.0.0"));
    }

    #[test]
    fn multibyte_requirement_does_not_panic_and_is_rejected() {
        assert!(parse_requirement("é==1").is_none());
        assert!(parse_requirement("café==1.0.0").is_none());
        assert!(parse_requirement("pkg-é==1").is_none());
        assert!(parse_requirement("é; python_version < \"3.8\"").is_none());
    }

    #[test]
    fn invalid_ascii_distribution_names_are_rejected() {
        assert!(parse_requirement("-foo==1").is_none());
        assert!(parse_requirement("foo-==1").is_none());
        assert!(parse_requirement("_foo==1").is_none());
        assert!(parse_requirement("foo_==1").is_none());
        assert!(parse_requirement(".foo==1").is_none());
        assert!(parse_requirement("foo.==1").is_none());
        assert!(parse_requirement("==1").is_none());
    }

    #[test]
    fn valid_ascii_names_still_parse() {
        assert_eq!(
            parse_requirement("requests==2.28.1").unwrap().name,
            "requests"
        );
        assert_eq!(parse_requirement("a==1").unwrap().name, "a");
        assert_eq!(parse_requirement("Django==4.2").unwrap().name, "Django");
        assert_eq!(
            parse_requirement("pkg.with_dot-dash==1").unwrap().name,
            "pkg.with_dot-dash"
        );
    }

    #[test]
    fn egg_fragment_rejects_invalid_names() {
        assert!(parse_requirement("git+https://example.com/repo.git#egg=é").is_none());
        assert!(parse_requirement("-e git+https://example.com/repo.git#egg=-invalid").is_none());
        let req = parse_requirement("git+https://example.com/repo.git#egg=requests").unwrap();
        assert_eq!(req.name, "requests");
        assert!(req.exact_version.is_none());
    }

    #[test]
    fn pipfile_and_poetry_reject_invalid_table_names() {
        assert!(parse_pipfile_version("é", "*").is_none());
        assert!(parse_pipfile_version("é", "==1.0.0").is_none());
        assert!(parse_poetry_version("é", "^1.0.0").is_none());
        assert!(parse_poetry_version("-foo", "1.0.0").is_none());
    }
}
