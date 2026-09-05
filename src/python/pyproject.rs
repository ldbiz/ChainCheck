//! `pyproject.toml` static dependency table parsing.

use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use crate::coverage::ArtifactStatus;
use crate::fsutil::read_utf8_bounded;
use crate::intelligence::EcosystemIntelligence;
use crate::model::PackageIdentity;

use super::spec::{parse_poetry_version, parse_requirement};
use super::{DET_PYPROJECT, FileScan, LIMIT_PYPROJECT, PEP735_MAX_DEPTH, emit_declaration};

pub fn scan_pyproject(path: &Path, intel: &EcosystemIntelligence) -> FileScan {
    match read_utf8_bounded(path, LIMIT_PYPROJECT) {
        crate::fsutil::TextReadOutcome::Text(text) => parse_pyproject(path, intel, &text),
        other => FileScan::failed(crate::fsutil::text_artifact_status(&other)),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingDeclaration {
    name: String,
    exact_version: Option<String>,
}

fn parse_pyproject(path: &Path, intel: &EcosystemIntelligence, text: &str) -> FileScan {
    let value: toml::Value = match toml::from_str(text) {
        Ok(v) => v,
        Err(_) => return FileScan::failed(ArtifactStatus::ParseFailed),
    };
    let mut pending = Vec::new();
    let mut parse_failed = false;

    let dynamic = project_dynamic_fields(&value);
    if let Some(deps) = value.get("project").and_then(|p| p.get("dependencies")) {
        if !dynamic.contains("dependencies") {
            parse_failed |= collect_dep_list(deps, &mut pending);
        }
    }
    if let Some(opt) = value
        .get("project")
        .and_then(|p| p.get("optional-dependencies"))
    {
        if !dynamic.contains("optional-dependencies") {
            parse_failed |= collect_optional_deps(opt, &mut pending);
        }
    }
    if let Some(req) = value.get("build-system").and_then(|b| b.get("requires")) {
        parse_failed |= collect_dep_list(req, &mut pending);
    }
    if let Some(groups) = value.get("dependency-groups") {
        parse_failed |= collect_dependency_groups(groups, &mut pending);
    }
    if let Some(poetry) = value.get("tool").and_then(|t| t.get("poetry")) {
        parse_failed |= collect_poetry_tables(poetry, &mut pending);
    }

    let pending = dedupe_declarations(pending);
    let mut findings = Vec::new();
    let mut evidence = Vec::new();
    for decl in pending {
        emit_declaration(
            intel,
            &decl.name,
            decl.exact_version.as_deref(),
            path,
            DET_PYPROJECT,
            &mut findings,
            &mut evidence,
        );
    }

    let status = if parse_failed {
        ArtifactStatus::ParseFailed
    } else {
        ArtifactStatus::Inspected
    };
    FileScan {
        status,
        findings,
        evidence,
    }
}

fn dedupe_declarations(pending: Vec<PendingDeclaration>) -> Vec<PendingDeclaration> {
    let mut by_name: BTreeMap<String, Vec<PendingDeclaration>> = BTreeMap::new();
    for decl in pending {
        let key = PackageIdentity::pypi(&decl.name).name().as_str().to_owned();
        by_name.entry(key).or_default().push(decl);
    }
    let mut out = Vec::new();
    for decls in by_name.into_values() {
        let mut exact: BTreeMap<String, PendingDeclaration> = BTreeMap::new();
        let mut identity_only: Option<PendingDeclaration> = None;
        for decl in decls {
            match &decl.exact_version {
                Some(version) => {
                    exact.entry(version.clone()).or_insert(decl);
                }
                None => {
                    if identity_only.is_none() {
                        identity_only = Some(decl);
                    }
                }
            }
        }
        if exact.is_empty() {
            if let Some(identity) = identity_only {
                out.push(identity);
            }
        } else {
            out.extend(exact.into_values());
        }
    }
    out
}

fn project_dynamic_fields(value: &toml::Value) -> HashSet<String> {
    value
        .get("project")
        .and_then(|p| p.get("dynamic"))
        .and_then(|d| d.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn collect_optional_deps(table: &toml::Value, pending: &mut Vec<PendingDeclaration>) -> bool {
    let Some(table) = table.as_table() else {
        return true;
    };
    let mut failed = false;
    for (_group, deps) in table {
        failed |= collect_dep_list(deps, pending);
    }
    failed
}

fn collect_dep_list(deps: &toml::Value, pending: &mut Vec<PendingDeclaration>) -> bool {
    let Some(list) = deps.as_array() else {
        return true;
    };
    let mut failed = false;
    for item in list {
        let Some(spec) = item.as_str() else {
            failed = true;
            continue;
        };
        if let Some(req) = parse_requirement(spec) {
            pending.push(PendingDeclaration {
                name: req.name,
                exact_version: req.exact_version,
            });
        }
    }
    failed
}

fn collect_poetry_tables(poetry: &toml::Value, pending: &mut Vec<PendingDeclaration>) -> bool {
    let mut failed = false;
    if let Some(deps) = poetry.get("dependencies") {
        failed |= collect_poetry_dep_table(deps, pending);
    }
    if let Some(groups) = poetry.get("group").and_then(|g| g.as_table()) {
        for (_name, group) in groups {
            if let Some(deps) = group.get("dependencies") {
                failed |= collect_poetry_dep_table(deps, pending);
            }
        }
    }
    failed
}

fn collect_poetry_dep_table(table: &toml::Value, pending: &mut Vec<PendingDeclaration>) -> bool {
    let Some(table) = table.as_table() else {
        return true;
    };
    let mut failed = false;
    for (name, spec) in table {
        if name == "python" {
            continue;
        }
        match spec {
            toml::Value::String(version) => {
                if let Some(req) = parse_poetry_version(name, version) {
                    pending.push(PendingDeclaration {
                        name: req.name,
                        exact_version: req.exact_version,
                    });
                }
            }
            toml::Value::Array(items) => {
                if is_poetry_multi_constraint_array(items) {
                    pending.push(PendingDeclaration {
                        name: name.clone(),
                        exact_version: None,
                    });
                } else {
                    failed = true;
                }
            }
            toml::Value::Table(inner) => {
                if inner.contains_key("git")
                    || inner.contains_key("path")
                    || inner.contains_key("url")
                {
                    pending.push(PendingDeclaration {
                        name: name.clone(),
                        exact_version: None,
                    });
                } else if let Some(version) = inner.get("version").and_then(|v| v.as_str()) {
                    if let Some(req) = parse_poetry_version(name, version) {
                        pending.push(PendingDeclaration {
                            name: req.name,
                            exact_version: req.exact_version,
                        });
                    }
                } else if is_poetry_package_table(inner) {
                    pending.push(PendingDeclaration {
                        name: name.clone(),
                        exact_version: None,
                    });
                } else {
                    failed = true;
                }
            }
            _ => failed = true,
        }
    }
    failed
}

const POETRY_PACKAGE_TABLE_KEYS: &[&str] = &[
    "version", "extras", "git", "path", "url", "branch", "tag", "rev", "markers", "source",
    "platform", "python", "optional",
];

fn is_poetry_package_table(table: &toml::Table) -> bool {
    table
        .keys()
        .any(|k| POETRY_PACKAGE_TABLE_KEYS.contains(&k.as_str()))
}

fn is_poetry_multi_constraint_array(items: &[toml::Value]) -> bool {
    !items.is_empty()
        && items.iter().all(|item| {
            item.as_table()
                .is_some_and(|table| is_poetry_package_table(table))
        })
}

fn collect_dependency_groups(groups: &toml::Value, pending: &mut Vec<PendingDeclaration>) -> bool {
    let Some(table) = groups.as_table() else {
        return true;
    };
    let mut failed = false;
    let mut by_name: BTreeMap<String, Vec<GroupItem>> = BTreeMap::new();
    let mut colliding = std::collections::BTreeSet::new();
    for (name, value) in table {
        let key = normalize_group_name(name);
        let (items, item_failed) = parse_group_items(value);
        failed |= item_failed;
        if by_name.contains_key(&key) {
            colliding.insert(key);
            continue;
        }
        by_name.insert(key, items);
    }
    if !colliding.is_empty() {
        return true;
    }

    let mut seen = std::collections::BTreeSet::new();
    for name in by_name.keys() {
        let mut stack = vec![name.clone()];
        match expand_group(name, &by_name, &mut stack, 0) {
            Ok(reqs) => {
                for req in reqs {
                    let key = (req.name.clone(), req.exact_version.clone());
                    if !seen.insert(key) {
                        continue;
                    }
                    pending.push(PendingDeclaration {
                        name: req.name,
                        exact_version: req.exact_version,
                    });
                }
            }
            Err(()) => failed = true,
        }
    }
    failed
}

#[derive(Clone, Debug)]
enum GroupItem {
    Requirement(String),
    IncludeGroup(String),
}

fn parse_group_items(value: &toml::Value) -> (Vec<GroupItem>, bool) {
    let Some(list) = value.as_array() else {
        return (Vec::new(), true);
    };
    let mut items = Vec::new();
    let mut failed = false;
    for item in list {
        match item {
            toml::Value::String(spec) => items.push(GroupItem::Requirement(spec.clone())),
            toml::Value::Table(table) => match include_group_name(table) {
                Some(name) => items.push(GroupItem::IncludeGroup(name)),
                None => failed = true,
            },
            _ => failed = true,
        }
    }
    (items, failed)
}

fn include_group_name(table: &toml::Table) -> Option<String> {
    if table.len() != 1 {
        return None;
    }
    table
        .get("include-group")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
}

fn expand_group(
    name: &str,
    all: &BTreeMap<String, Vec<GroupItem>>,
    stack: &mut Vec<String>,
    depth: usize,
) -> Result<Vec<super::spec::ParsedRequirement>, ()> {
    if depth > PEP735_MAX_DEPTH {
        return Err(());
    }
    let Some(items) = all.get(name) else {
        return Err(());
    };
    let mut out = Vec::new();
    for item in items {
        match item {
            GroupItem::IncludeGroup(raw) => {
                let key = normalize_group_name(raw);
                if stack.contains(&key) {
                    return Err(());
                }
                if !all.contains_key(&key) {
                    return Err(());
                }
                stack.push(key.clone());
                let nested = expand_group(&key, all, stack, depth + 1)?;
                stack.pop();
                out.extend(nested);
            }
            GroupItem::Requirement(spec) => {
                if let Some(req) = parse_requirement(spec) {
                    out.push(req);
                }
            }
        }
    }
    Ok(out)
}

fn normalize_group_name(name: &str) -> String {
    let mut out = String::new();
    let mut prev_sep = false;
    for ch in name.chars() {
        if ch == '-' || ch == '_' || ch == '.' {
            if !prev_sep {
                out.push('-');
                prev_sep = true;
            }
        } else {
            out.push(ch.to_ascii_lowercase());
            prev_sep = false;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intelligence::{EcosystemIntelligence, parse_malware_feed};
    use crate::model::{Ecosystem, FindingSubject};

    const TINY: &[u8] = br#"[{"package_name":"evil","version":"1.0.0","reason":"MALWARE"}]"#;

    #[test]
    fn project_name_version_do_not_emit() {
        let intel =
            EcosystemIntelligence::Available(parse_malware_feed(TINY, Ecosystem::Pypi).unwrap());
        let text = r#"
[project]
name = "evil"
version = "1.0.0"
dependencies = ["benign==1.0.0"]
"#;
        let scan = parse_pyproject(Path::new("pyproject.toml"), &intel, text);
        assert!(scan.findings.is_empty());
        assert_eq!(scan.status, ArtifactStatus::Inspected);
    }

    #[test]
    fn poetry_bare_version_is_exact() {
        let intel =
            EcosystemIntelligence::Available(parse_malware_feed(TINY, Ecosystem::Pypi).unwrap());
        let text = r#"
[tool.poetry.dependencies]
evil = "1.0.0"
"#;
        let scan = parse_pyproject(Path::new("pyproject.toml"), &intel, text);
        assert_eq!(scan.findings.len(), 1);
        assert_eq!(scan.evidence.len(), 1);
        match &scan.findings[0].subject {
            FindingSubject::PackageExact(key) => {
                assert_eq!(key.version.as_str(), "1.0.0");
            }
            other => panic!("expected exact package, got {other:?}"),
        }
    }

    #[test]
    fn poetry_caret_is_identity_only() {
        let intel = EcosystemIntelligence::Available(
            parse_malware_feed(
                br#"[{"package_name":"evil","version":"*","reason":"MALWARE"}]"#,
                Ecosystem::Pypi,
            )
            .unwrap(),
        );
        let text = r#"
[tool.poetry.dependencies]
evil = "^1.0.0"
"#;
        let scan = parse_pyproject(Path::new("pyproject.toml"), &intel, text);
        assert_eq!(scan.findings.len(), 1);
        assert!(scan.evidence.is_empty());
        assert!(matches!(
            scan.findings[0].subject,
            FindingSubject::PackageIdentity(_)
        ));
    }

    #[test]
    fn pep735_include_group_emits_nested_requirement() {
        let intel = EcosystemIntelligence::Available(
            parse_malware_feed(
                br#"[{"package_name":"mypy","version":"1.2.3","reason":"MALWARE"}]"#,
                Ecosystem::Pypi,
            )
            .unwrap(),
        );
        let text = r#"
[dependency-groups]
typing = ["mypy==1.2.3"]
test = ["pytest", { include-group = "typing" }]
"#;
        let scan = parse_pyproject(Path::new("pyproject.toml"), &intel, text);
        assert_eq!(scan.status, ArtifactStatus::Inspected);
        assert_eq!(scan.findings.len(), 1);
        assert_eq!(scan.evidence.len(), 1);
    }

    #[test]
    fn pep735_missing_group_is_partial() {
        let intel =
            EcosystemIntelligence::Available(parse_malware_feed(TINY, Ecosystem::Pypi).unwrap());
        let text = r#"
[dependency-groups]
test = [{ include-group = "missing" }]
"#;
        let scan = parse_pyproject(Path::new("pyproject.toml"), &intel, text);
        assert_eq!(scan.status, ArtifactStatus::ParseFailed);
        assert!(scan.findings.is_empty());
    }

    #[test]
    fn pep735_cycle_is_partial() {
        let intel =
            EcosystemIntelligence::Available(parse_malware_feed(TINY, Ecosystem::Pypi).unwrap());
        let text = r#"
[dependency-groups]
a = [{ include-group = "b" }]
b = [{ include-group = "a" }]
"#;
        let scan = parse_pyproject(Path::new("pyproject.toml"), &intel, text);
        assert_eq!(scan.status, ArtifactStatus::ParseFailed);
    }

    #[test]
    fn pep735_normalised_name_collision_is_partial() {
        let intel = EcosystemIntelligence::Available(
            parse_malware_feed(
                br#"[{"package_name":"mypy","version":"1.2.3","reason":"MALWARE"}]"#,
                Ecosystem::Pypi,
            )
            .unwrap(),
        );
        let text = r#"
[dependency-groups]
typing = ["mypy==1.2.3"]
Typing = ["benign==1.0"]
"#;
        let scan = parse_pyproject(Path::new("pyproject.toml"), &intel, text);
        assert_eq!(scan.status, ArtifactStatus::ParseFailed);
        assert!(scan.findings.is_empty());
        assert!(scan.evidence.is_empty());
    }

    #[test]
    fn pep735_invalid_include_object_is_partial() {
        let intel =
            EcosystemIntelligence::Available(parse_malware_feed(TINY, Ecosystem::Pypi).unwrap());
        let text = r#"
[dependency-groups]
test = [{ include-group = "typing", extra = 1 }]
"#;
        let scan = parse_pyproject(Path::new("pyproject.toml"), &intel, text);
        assert_eq!(scan.status, ArtifactStatus::ParseFailed);
    }

    #[test]
    fn invalid_sibling_does_not_drop_valid_dependency() {
        let intel =
            EcosystemIntelligence::Available(parse_malware_feed(TINY, Ecosystem::Pypi).unwrap());
        let text = r#"
[project]
dependencies = [
  123,
  "evil==1.0.0",
]
"#;
        let scan = parse_pyproject(Path::new("pyproject.toml"), &intel, text);
        assert_eq!(scan.status, ArtifactStatus::ParseFailed);
        assert_eq!(scan.findings.len(), 1);
        assert_eq!(scan.evidence.len(), 1);
    }

    #[test]
    fn optional_dependencies_recover_valid_string_after_invalid_sibling() {
        let intel =
            EcosystemIntelligence::Available(parse_malware_feed(TINY, Ecosystem::Pypi).unwrap());
        let text = r#"
[project.optional-dependencies]
dev = [123, "evil==1.0.0"]
"#;
        let scan = parse_pyproject(Path::new("pyproject.toml"), &intel, text);
        assert_eq!(scan.status, ArtifactStatus::ParseFailed);
        assert_eq!(scan.findings.len(), 1);
        assert_eq!(scan.evidence.len(), 1);
    }

    #[test]
    fn build_system_requires_recover_valid_string_after_invalid_sibling() {
        let intel =
            EcosystemIntelligence::Available(parse_malware_feed(TINY, Ecosystem::Pypi).unwrap());
        let text = r#"
[build-system]
requires = [true, "evil==1.0.0"]
"#;
        let scan = parse_pyproject(Path::new("pyproject.toml"), &intel, text);
        assert_eq!(scan.status, ArtifactStatus::ParseFailed);
        assert_eq!(scan.findings.len(), 1);
        assert_eq!(scan.evidence.len(), 1);
    }

    #[test]
    fn poetry_and_project_dedup_exact() {
        let intel =
            EcosystemIntelligence::Available(parse_malware_feed(TINY, Ecosystem::Pypi).unwrap());
        let text = r#"
[project]
dependencies = ["evil==1.0.0"]

[tool.poetry.dependencies]
evil = "1.0.0"
"#;
        let scan = parse_pyproject(Path::new("pyproject.toml"), &intel, text);
        assert_eq!(scan.findings.len(), 1);
        assert_eq!(scan.evidence.len(), 1);
    }

    #[test]
    fn distinct_exact_versions_are_retained() {
        let intel = EcosystemIntelligence::Available(
            parse_malware_feed(
                br#"[{"package_name":"evil","version":"2.0.0","reason":"MALWARE"}]"#,
                Ecosystem::Pypi,
            )
            .unwrap(),
        );
        let text = r#"
[project]
dependencies = ["evil==1.0.0", "evil==2.0.0"]
"#;
        let scan = parse_pyproject(Path::new("pyproject.toml"), &intel, text);
        assert_eq!(scan.status, ArtifactStatus::Inspected);
        assert_eq!(scan.findings.len(), 1);
        assert_eq!(scan.evidence.len(), 1);
        match &scan.findings[0].subject {
            FindingSubject::PackageExact(key) => {
                assert_eq!(key.version.as_str(), "2.0.0");
            }
            other => panic!("expected exact 2.0.0, got {other:?}"),
        }
    }

    #[test]
    fn distinct_exact_versions_across_project_and_poetry_are_retained() {
        let intel = EcosystemIntelligence::Available(
            parse_malware_feed(
                br#"[{"package_name":"evil","version":"2.0.0","reason":"MALWARE"}]"#,
                Ecosystem::Pypi,
            )
            .unwrap(),
        );
        let text = r#"
[project]
dependencies = ["evil==1.0.0"]

[tool.poetry.dependencies]
evil = "2.0.0"
"#;
        let scan = parse_pyproject(Path::new("pyproject.toml"), &intel, text);
        assert_eq!(scan.status, ArtifactStatus::Inspected);
        assert_eq!(scan.findings.len(), 1);
        match &scan.findings[0].subject {
            FindingSubject::PackageExact(key) => {
                assert_eq!(key.version.as_str(), "2.0.0");
            }
            other => panic!("expected exact 2.0.0, got {other:?}"),
        }
    }

    #[test]
    fn poetry_multi_constraint_array_is_identity_only() {
        let intel = EcosystemIntelligence::Available(
            parse_malware_feed(
                br#"[{"package_name":"evil","version":"*","reason":"MALWARE"}]"#,
                Ecosystem::Pypi,
            )
            .unwrap(),
        );
        let text = r#"
[tool.poetry.dependencies]
evil = [
  { version = ">=1,<2", python = "<3.12" },
  { version = ">=2", python = ">=3.12" },
]
"#;
        let scan = parse_pyproject(Path::new("pyproject.toml"), &intel, text);
        assert_eq!(scan.status, ArtifactStatus::Inspected);
        assert_eq!(scan.findings.len(), 1);
        assert!(scan.evidence.is_empty());
        assert!(matches!(
            scan.findings[0].subject,
            FindingSubject::PackageIdentity(_)
        ));
        assert_eq!(scan.findings[0].severity, crate::model::Severity::Medium);
    }

    #[test]
    fn poetry_malformed_array_is_parse_failed() {
        let intel =
            EcosystemIntelligence::Available(parse_malware_feed(TINY, Ecosystem::Pypi).unwrap());
        let text = r#"
[tool.poetry.dependencies]
evil = [1, "2.0.0"]
"#;
        let scan = parse_pyproject(Path::new("pyproject.toml"), &intel, text);
        assert_eq!(scan.status, ArtifactStatus::ParseFailed);
        assert!(scan.findings.is_empty());
        assert!(scan.evidence.is_empty());
    }
}
