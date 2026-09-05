//! `requirements*.txt` declaration parsing with bounded includes and roles.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use crate::coverage::ArtifactStatus;
use crate::fsutil::read_bounded;
use crate::intelligence::EcosystemIntelligence;

use super::spec::parse_requirement;
use super::{
    DET_REQUIREMENTS, FileScan, INCLUDE_MAX_DEPTH, INCLUDE_MAX_FILES, LIMIT_REQUIREMENTS,
    emit_declaration,
};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct PathRoles {
    discovered: bool,
    requirement_include: bool,
    constraint: bool,
}

impl PathRoles {
    fn has_declaration_semantics(self) -> bool {
        if self.requirement_include {
            true
        } else if self.constraint {
            false
        } else {
            self.discovered
        }
    }
}

#[derive(Clone, Debug)]
struct IncludeRef {
    target: PathBuf,
    constraint: bool,
    problem: Option<ArtifactStatus>,
}

struct GraphState {
    roles: BTreeMap<PathBuf, PathRoles>,
    reads: BTreeMap<PathBuf, Result<String, ArtifactStatus>>,
    includes: BTreeMap<PathBuf, Vec<IncludeRef>>,
    opened: BTreeSet<PathBuf>,
}

pub fn scan_requirements_files(
    paths: &[PathBuf],
    intel: &EcosystemIntelligence,
    include_roots: &[PathBuf],
) -> Vec<(PathBuf, FileScan)> {
    let mut state = GraphState {
        roles: BTreeMap::new(),
        reads: BTreeMap::new(),
        includes: BTreeMap::new(),
        opened: BTreeSet::new(),
    };
    let mut seeds: Vec<PathBuf> = paths.iter().cloned().collect();
    seeds.sort();
    seeds.dedup();
    let seed_set: BTreeSet<PathBuf> = seeds.iter().cloned().collect();
    for seed in &seeds {
        state.roles.entry(seed.clone()).or_default().discovered = true;
        ingest_requirements_file(seed, include_roots, &mut state);
    }
    resolve_roles_and_includes(&seed_set, include_roots, &mut state);
    mark_requirement_cycles(&mut state);

    let mut statuses: BTreeMap<PathBuf, ArtifactStatus> = BTreeMap::new();
    let mut scans: BTreeMap<PathBuf, FileScan> = BTreeMap::new();

    let mut candidates: BTreeSet<PathBuf> = state.roles.keys().cloned().collect();
    candidates.extend(state.reads.keys().cloned());
    for refs in state.includes.values() {
        for r in refs {
            candidates.insert(r.target.clone());
        }
    }

    for path in &candidates {
        let roles = state.roles.get(path).copied().unwrap_or_default();
        if !roles.has_declaration_semantics() {
            continue;
        }
        let scan = scan_declarations(path, intel, &state);
        statuses.insert(path.clone(), scan.status);
        scans.insert(path.clone(), scan);
    }

    for path in &candidates {
        let roles = state.roles.get(path).copied().unwrap_or_default();
        if roles.has_declaration_semantics() {
            continue;
        }
        if let Some(refs) = state.includes.get(path) {
            for r in refs {
                if r.constraint {
                    continue;
                }
                if let Some(problem) = r.problem {
                    statuses.entry(r.target.clone()).or_insert(problem);
                }
            }
        }
        if !roles.requirement_include {
            continue;
        }
        if let Some(read) = state.reads.get(path) {
            let status = match read {
                Ok(_) => ArtifactStatus::Inspected,
                Err(status) => *status,
            };
            statuses.entry(path.clone()).or_insert(status);
            scans.entry(path.clone()).or_insert_with(|| match read {
                Ok(_) => FileScan {
                    status: ArtifactStatus::Inspected,
                    findings: Vec::new(),
                    evidence: Vec::new(),
                },
                Err(status) => FileScan::failed(*status),
            });
        }
    }

    for path in &candidates {
        for r in state.includes.get(path).into_iter().flatten() {
            if r.constraint {
                continue;
            }
            if let Some(problem) = r.problem {
                statuses.entry(r.target.clone()).or_insert(problem);
                scans
                    .entry(r.target.clone())
                    .or_insert_with(|| FileScan::failed(problem));
            }
        }
    }

    propagate_include_failures(&state, &mut statuses);

    for (path, status) in &statuses {
        let roles = state.roles.get(path).copied().unwrap_or_default();
        let keep = roles.has_declaration_semantics()
            || roles.requirement_include
            || scans.contains_key(path);
        if !keep {
            continue;
        }
        let scan = scans.entry(path.clone()).or_insert_with(|| FileScan {
            status: *status,
            findings: Vec::new(),
            evidence: Vec::new(),
        });
        if scan.status == ArtifactStatus::Inspected && *status != ArtifactStatus::Inspected {
            scan.status = *status;
        } else if scan.status == ArtifactStatus::Inspected {
            scan.status = *status;
        }
    }

    scans.into_iter().collect()
}

fn ingest_requirements_file(path: &Path, include_roots: &[PathBuf], state: &mut GraphState) {
    if state.reads.contains_key(path) {
        return;
    }
    let read = read_requirements_bytes(path);
    state.reads.insert(path.to_path_buf(), read.clone());
    if let Ok(text) = read {
        state.includes.insert(
            path.to_path_buf(),
            parse_include_refs(path, &text, include_roots),
        );
    }
}

fn parse_include_refs(path: &Path, text: &str, include_roots: &[PathBuf]) -> Vec<IncludeRef> {
    let mut refs = Vec::new();
    for line in logical_lines(text) {
        let line = prepare_requirement_line(&line);
        if line.is_empty() || is_pip_option_line(&line) {
            continue;
        }
        let Some((include, is_constraint)) = parse_include_line(&line) else {
            continue;
        };
        if is_remote_include(include) {
            refs.push(IncludeRef {
                target: PathBuf::from(include),
                constraint: is_constraint,
                problem: Some(ArtifactStatus::UnsupportedFormat),
            });
            continue;
        }
        match resolve_include(path, include, include_roots) {
            IncludeResolve::InScope(target) => refs.push(IncludeRef {
                target,
                constraint: is_constraint,
                problem: None,
            }),
            IncludeResolve::OutOfScope(target) | IncludeResolve::SymlinkEscape(target) => {
                if !is_constraint {
                    refs.push(IncludeRef {
                        target,
                        constraint: false,
                        problem: Some(ArtifactStatus::UnsupportedFormat),
                    });
                }
            }
            IncludeResolve::Invalid => {
                if !is_constraint {
                    refs.push(IncludeRef {
                        target: path.to_path_buf(),
                        constraint: false,
                        problem: Some(ArtifactStatus::ParseFailed),
                    });
                }
            }
        }
    }
    refs
}

fn resolve_roles_and_includes(
    seeds: &BTreeSet<PathBuf>,
    include_roots: &[PathBuf],
    state: &mut GraphState,
) {
    let mut changed = true;
    while changed {
        changed = false;
        changed |= apply_constraint_edges(state, true);
        changed |= apply_requirement_include_edges(state);
        changed |= apply_constraint_edges(state, false);
        changed |= expand_requirement_includes(seeds, include_roots, state);
    }
}

fn declaration_paths(state: &GraphState) -> Vec<PathBuf> {
    state
        .roles
        .iter()
        .filter(|(_, roles)| roles.has_declaration_semantics())
        .map(|(path, _)| path.clone())
        .collect()
}

fn constraint_only_paths(state: &GraphState) -> Vec<PathBuf> {
    state
        .roles
        .iter()
        .filter(|(_, roles)| roles.constraint && !roles.requirement_include)
        .map(|(path, _)| path.clone())
        .collect()
}

fn apply_constraint_edges(state: &mut GraphState, from_declaration_sources: bool) -> bool {
    let sources = if from_declaration_sources {
        declaration_paths(state)
    } else {
        constraint_only_paths(state)
    };
    let mut changed = false;
    for path in sources {
        let Some(refs) = state.includes.get(&path).cloned() else {
            continue;
        };
        for r in refs {
            let mark_constraint = if from_declaration_sources {
                r.constraint
            } else {
                r.problem.is_none()
            };
            if !mark_constraint {
                continue;
            }
            let roles = state.roles.entry(r.target.clone()).or_default();
            if !roles.constraint {
                roles.constraint = true;
                changed = true;
            }
        }
    }
    changed
}

fn apply_requirement_include_edges(state: &mut GraphState) -> bool {
    let mut changed = false;
    for path in declaration_paths(state) {
        let Some(refs) = state.includes.get(&path).cloned() else {
            continue;
        };
        for r in refs {
            if r.constraint || r.problem.is_some() {
                continue;
            }
            let roles = state.roles.entry(r.target.clone()).or_default();
            if !roles.requirement_include {
                roles.requirement_include = true;
                changed = true;
            }
        }
    }
    changed
}

fn expand_requirement_includes(
    seeds: &BTreeSet<PathBuf>,
    include_roots: &[PathBuf],
    state: &mut GraphState,
) -> bool {
    let mut to_open: Vec<PathBuf> = state
        .roles
        .iter()
        .filter(|(path, roles)| {
            roles.requirement_include && !state.reads.contains_key(*path) && !seeds.contains(*path)
        })
        .map(|(path, _)| path.clone())
        .collect();
    to_open.sort();
    if to_open.is_empty() {
        return false;
    }
    let mut changed = false;
    let depths = include_depths(seeds, state);
    for path in to_open {
        let depth = depths.get(&path).copied().unwrap_or(1);
        if depth > INCLUDE_MAX_DEPTH {
            state
                .reads
                .entry(path.clone())
                .or_insert(Err(ArtifactStatus::ParseFailed));
            changed = true;
            continue;
        }
        if state.opened.len() >= INCLUDE_MAX_FILES {
            state
                .reads
                .entry(path.clone())
                .or_insert(Err(ArtifactStatus::ParseFailed));
            changed = true;
            continue;
        }
        state.opened.insert(path.clone());
        ingest_requirements_file(&path, include_roots, state);
        changed = true;
    }
    changed
}

fn include_depths(seeds: &BTreeSet<PathBuf>, state: &GraphState) -> BTreeMap<PathBuf, usize> {
    let mut depths: BTreeMap<PathBuf, usize> = BTreeMap::new();
    let mut queue: Vec<PathBuf> = Vec::new();
    for seed in seeds {
        depths.insert(seed.clone(), 0);
        queue.push(seed.clone());
    }
    while let Some(path) = queue.pop() {
        let depth = depths[&path];
        let Some(refs) = state.includes.get(&path) else {
            continue;
        };
        let parent_decl = state
            .roles
            .get(&path)
            .is_some_and(|roles| roles.has_declaration_semantics());
        if !parent_decl {
            continue;
        }
        for r in refs {
            if r.constraint || r.problem.is_some() {
                continue;
            }
            let next = depth + 1;
            let existing = depths.get(&r.target).copied();
            if existing.is_none_or(|d| next < d) {
                depths.insert(r.target.clone(), next);
                queue.push(r.target.clone());
            }
        }
    }
    depths
}

fn mark_requirement_cycles(state: &mut GraphState) {
    let decl = declaration_paths(state);
    for parent in decl {
        let Some(refs) = state.includes.get(&parent).cloned() else {
            continue;
        };
        for (idx, r) in refs.iter().enumerate() {
            if r.constraint || r.problem.is_some() {
                continue;
            }
            if reaches_via_requirement_include(&r.target, &parent, state, &mut BTreeSet::new()) {
                if let Some(slot) = state.includes.get_mut(&parent).and_then(|v| v.get_mut(idx)) {
                    slot.problem = Some(ArtifactStatus::ParseFailed);
                }
            }
        }
    }
}

fn reaches_via_requirement_include(
    from: &Path,
    target: &Path,
    state: &GraphState,
    seen: &mut BTreeSet<PathBuf>,
) -> bool {
    if from == target {
        return true;
    }
    if !seen.insert(from.to_path_buf()) {
        return false;
    }
    let parent_decl = state
        .roles
        .get(from)
        .is_some_and(|roles| roles.has_declaration_semantics());
    if !parent_decl {
        return false;
    }
    let Some(refs) = state.includes.get(from) else {
        return false;
    };
    refs.iter().any(|r| {
        !r.constraint
            && r.problem.is_none()
            && reaches_via_requirement_include(&r.target, target, state, seen)
    })
}

fn scan_declarations(path: &Path, intel: &EcosystemIntelligence, state: &GraphState) -> FileScan {
    match state.reads.get(path) {
        None => FileScan::failed(ArtifactStatus::ParseFailed),
        Some(Err(status)) => FileScan::failed(*status),
        Some(Ok(text)) => {
            let mut findings = Vec::new();
            let mut evidence = Vec::new();
            let mut parse_failed = false;
            for line in logical_lines(text) {
                let line = prepare_requirement_line(&line);
                if line.is_empty() {
                    continue;
                }
                if is_pip_option_line(&line) {
                    continue;
                }
                if parse_include_line(&line).is_some() {
                    continue;
                }
                if line.contains("${") {
                    continue;
                }
                if let Some(req) = parse_requirement(&line) {
                    emit_declaration(
                        intel,
                        &req.name,
                        req.exact_version.as_deref(),
                        path,
                        DET_REQUIREMENTS,
                        &mut findings,
                        &mut evidence,
                    );
                } else if !line.starts_with('-') {
                    parse_failed = true;
                }
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
    }
}

fn propagate_include_failures(
    state: &GraphState,
    statuses: &mut BTreeMap<PathBuf, ArtifactStatus>,
) {
    let mut changed = true;
    while changed {
        changed = false;
        for (parent, refs) in &state.includes {
            let parent_decl = state
                .roles
                .get(parent)
                .is_some_and(|roles| roles.has_declaration_semantics());
            if !parent_decl {
                continue;
            }
            let Some(parent_status) = statuses.get(parent).copied() else {
                continue;
            };
            if parent_status != ArtifactStatus::Inspected {
                continue;
            }
            let mut next = None;
            for r in refs {
                if r.constraint {
                    continue;
                }
                if let Some(problem) = r.problem {
                    next = Some(problem);
                    break;
                }
                if state.opened.contains(&r.target)
                    && state.roles.get(&r.target).is_some_and(|roles| {
                        roles.has_declaration_semantics() || roles.requirement_include
                    })
                    && !state.reads.contains_key(&r.target)
                {
                    next = Some(ArtifactStatus::ParseFailed);
                    break;
                }
                if let Some(child) = statuses.get(&r.target) {
                    if *child != ArtifactStatus::Inspected {
                        next = Some(if *child == ArtifactStatus::UnsupportedFormat {
                            ArtifactStatus::UnsupportedFormat
                        } else {
                            ArtifactStatus::ParseFailed
                        });
                        break;
                    }
                } else if state.roles.get(&r.target).is_some_and(|roles| {
                    roles.requirement_include || roles.has_declaration_semantics()
                }) {
                    next = Some(ArtifactStatus::ParseFailed);
                    break;
                }
            }
            if let Some(status) = next {
                statuses.insert(parent.clone(), status);
                changed = true;
            }
        }
    }
}

fn read_requirements_bytes(path: &Path) -> Result<String, ArtifactStatus> {
    match read_bounded(path, LIMIT_REQUIREMENTS) {
        crate::fsutil::ReadOutcome::Read(bytes) => match decode_requirements_bytes(&bytes) {
            Ok(text) => Ok(text),
            Err(status) => Err(status),
        },
        crate::fsutil::ReadOutcome::StatFailed { .. } => Err(ArtifactStatus::StatFailed),
        crate::fsutil::ReadOutcome::Unreadable { .. }
        | crate::fsutil::ReadOutcome::NotRegular
        | crate::fsutil::ReadOutcome::Symlink => Err(ArtifactStatus::Unreadable),
        crate::fsutil::ReadOutcome::Oversized { .. } => Err(ArtifactStatus::Oversized),
    }
}

fn decode_requirements_bytes(bytes: &[u8]) -> Result<String, ArtifactStatus> {
    match detect_encoding(bytes) {
        EncodingPolicy::Utf8 => match std::str::from_utf8(strip_bom(bytes)) {
            Ok(text) => Ok(text.to_owned()),
            Err(_) => Err(ArtifactStatus::ParseFailed),
        },
        EncodingPolicy::Unsupported => Err(ArtifactStatus::UnsupportedFormat),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EncodingPolicy {
    Utf8,
    Unsupported,
}

fn strip_bom(bytes: &[u8]) -> &[u8] {
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        &bytes[3..]
    } else {
        bytes
    }
}

fn detect_encoding(bytes: &[u8]) -> EncodingPolicy {
    let body = strip_bom(bytes);
    for line in first_two_lines(body) {
        if let Some(enc) = pep263_encoding(line) {
            return if is_utf8_encoding(&enc) {
                EncodingPolicy::Utf8
            } else {
                EncodingPolicy::Unsupported
            };
        }
    }
    EncodingPolicy::Utf8
}

fn first_two_lines(bytes: &[u8]) -> Vec<&[u8]> {
    let mut lines = Vec::new();
    let mut start = 0usize;
    let mut i = 0usize;
    while i < bytes.len() && lines.len() < 2 {
        if bytes[i] == b'\n' {
            let end = if i > start && bytes[i - 1] == b'\r' {
                i - 1
            } else {
                i
            };
            lines.push(&bytes[start..end]);
            start = i + 1;
        }
        i += 1;
    }
    if lines.len() < 2 && start < bytes.len() {
        lines.push(&bytes[start..]);
    }
    lines
}

fn pep263_encoding(line: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(line).ok()?;
    let trimmed = text.trim();
    let lower = trimmed.to_ascii_lowercase();
    let rest = lower
        .strip_prefix("#")
        .or_else(|| lower.strip_prefix("# -*-"))
        .or_else(|| lower.strip_prefix("#-*-"))?;
    let coding_idx = rest.find("coding")?;
    let after = &rest[coding_idx + "coding".len()..];
    let after = after.trim_start_matches([':', '=']).trim();
    let enc = after
        .split_whitespace()
        .next()?
        .trim_end_matches("-*-")
        .trim_end_matches('#')
        .trim();
    if enc.is_empty() {
        None
    } else {
        Some(enc.to_owned())
    }
}

fn is_utf8_encoding(enc: &str) -> bool {
    matches!(enc, "utf-8" | "utf8" | "utf-8-sig")
}

fn logical_lines(text: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for raw in text.lines() {
        if raw.ends_with('\\') {
            current.push_str(&raw[..raw.len() - 1]);
            continue;
        }
        current.push_str(raw);
        lines.push(std::mem::take(&mut current));
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

fn prepare_requirement_line(line: &str) -> String {
    let without_comment = strip_pip_comment(line);
    strip_per_requirement_options(without_comment)
        .trim()
        .to_owned()
}

fn strip_pip_comment(line: &str) -> &str {
    let mut in_quote = None;
    let mut prev_ws = true;
    for (idx, ch) in line.char_indices() {
        if let Some(q) = in_quote {
            if ch == q {
                in_quote = None;
            }
            prev_ws = false;
            continue;
        }
        if ch == '"' || ch == '\'' {
            in_quote = Some(ch);
            prev_ws = false;
            continue;
        }
        if ch == '#' && (prev_ws || idx == 0) {
            return &line[..idx];
        }
        prev_ws = ch.is_whitespace();
    }
    line
}

fn strip_per_requirement_options(line: &str) -> &str {
    let mut in_quote = None;
    let mut token_start = None;
    let bytes = line.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let ch = bytes[i] as char;
        if let Some(q) = in_quote {
            if ch == q {
                in_quote = None;
            }
            i += 1;
            continue;
        }
        if ch == '"' || ch == '\'' {
            in_quote = Some(ch);
            if token_start.is_none() {
                token_start = Some(i);
            }
            i += 1;
            continue;
        }
        if ch.is_whitespace() {
            if let Some(start) = token_start.take() {
                if is_per_requirement_option(&line[start..i]) {
                    return line[..start].trim_end();
                }
            }
            i += 1;
            continue;
        }
        if token_start.is_none() {
            token_start = Some(i);
        }
        i += 1;
    }
    if let Some(start) = token_start {
        if is_per_requirement_option(&line[start..]) {
            return line[..start].trim_end();
        }
    }
    line
}

fn is_per_requirement_option(token: &str) -> bool {
    token == "--hash"
        || token.starts_with("--hash=")
        || token == "--config-settings"
        || token.starts_with("--config-settings=")
}

fn is_pip_option_line(line: &str) -> bool {
    const OPTIONS: &[&str] = &[
        "--index-url",
        "-i",
        "--extra-index-url",
        "--no-index",
        "--find-links",
        "-f",
        "--trusted-host",
        "--require-hashes",
        "--no-require-hashes",
        "--pre",
        "--no-binary",
        "--only-binary",
        "--prefer-binary",
        "--hash",
        "--config-settings",
    ];
    let token = line.split_whitespace().next().unwrap_or("");
    OPTIONS.iter().any(|opt| *opt == token)
}

fn parse_include_line(line: &str) -> Option<(&str, bool)> {
    let mut parts = line.split_whitespace();
    let flag = parts.next()?;
    match flag {
        "-r" | "--requirement" => parts.next().map(|p| (p, false)),
        "-c" | "--constraint" => parts.next().map(|p| (p, true)),
        _ => None,
    }
}

fn is_remote_include(path: &str) -> bool {
    path.starts_with("http://")
        || path.starts_with("https://")
        || path.starts_with("ftp://")
        || path.starts_with("file:")
}

enum IncludeResolve {
    InScope(PathBuf),
    OutOfScope(PathBuf),
    SymlinkEscape(PathBuf),
    Invalid,
}

fn resolve_include(base: &Path, include: &str, roots: &[PathBuf]) -> IncludeResolve {
    let joined = if include.starts_with('/') {
        PathBuf::from(include)
    } else {
        let Some(parent) = base.parent() else {
            return IncludeResolve::Invalid;
        };
        parent.join(include)
    };
    let normalized = normalize_lexical(&joined);
    if !roots
        .iter()
        .any(|root| is_lexical_inside(&normalized, root))
    {
        return IncludeResolve::OutOfScope(normalized);
    }
    if intermediate_dir_symlink_inside_roots(&normalized, roots) {
        return IncludeResolve::SymlinkEscape(normalized);
    }
    IncludeResolve::InScope(normalized)
}

fn normalize_lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => out.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => match out.components().next_back() {
                Some(Component::Normal(_)) => {
                    out.pop();
                }
                Some(Component::RootDir) | Some(Component::Prefix(_)) => {}
                _ => out.push(".."),
            },
            Component::Normal(name) => out.push(name),
        }
    }
    out
}

fn is_lexical_inside(path: &Path, root: &Path) -> bool {
    let path = normalize_lexical(path);
    let root = normalize_lexical(root);
    path == root || path.starts_with(&root)
}

fn intermediate_dir_symlink_inside_roots(path: &Path, roots: &[PathBuf]) -> bool {
    let mut current = PathBuf::new();
    let components: Vec<_> = path.components().collect();
    for (idx, component) in components.iter().enumerate() {
        current.push(component.as_os_str());
        if idx + 1 == components.len() {
            break;
        }
        if !roots.iter().any(|root| {
            let root = normalize_lexical(root);
            current.starts_with(&root) && current != root
        }) {
            continue;
        }
        if let Ok(meta) = fs::symlink_metadata(&current) {
            if meta.file_type().is_symlink() {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intelligence::{EcosystemIntelligence, parse_malware_feed};
    use crate::model::Ecosystem;

    const TINY: &[u8] = br#"[{"package_name":"evil","version":"1.2.3","reason":"MALWARE"}]"#;

    fn intel() -> EcosystemIntelligence {
        EcosystemIntelligence::Available(parse_malware_feed(TINY, Ecosystem::Pypi).unwrap())
    }

    fn scan_in(paths: &[PathBuf], root: &Path) -> Vec<(PathBuf, FileScan)> {
        scan_requirements_files(paths, &intel(), &[root.to_path_buf()])
    }

    #[test]
    fn constraint_only_file_is_not_scanned() {
        let base = std::env::temp_dir().join(format!("req-c-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        let main = base.join("requirements.txt");
        let constraints = base.join("requirements-constraints.txt");
        std::fs::write(&main, "-c requirements-constraints.txt\n").unwrap();
        std::fs::write(&constraints, "evil==1.2.3\n").unwrap();
        let results = scan_in(&[main.clone()], &base);
        assert_eq!(results.len(), 1);
        assert!(results[0].1.findings.is_empty());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn requirement_include_wins_over_constraint() {
        let base = std::env::temp_dir().join(format!("req-rc-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        let shared = base.join("requirements-shared.txt");
        std::fs::write(&shared, "evil==1.2.3\n").unwrap();
        let main = base.join("requirements.txt");
        std::fs::write(
            &main,
            "-r requirements-shared.txt\n-c requirements-shared.txt\n",
        )
        .unwrap();
        let results = scan_in(&[main], &base);
        let findings: usize = results.iter().map(|(_, s)| s.findings.len()).sum();
        assert_eq!(findings, 1);
        let child = results
            .iter()
            .find(|(p, _)| p.ends_with("requirements-shared.txt"));
        assert!(child.is_some());
        assert_eq!(child.unwrap().1.findings.len(), 1);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn latin1_cookie_with_invalid_utf8_is_unsupported() {
        let mut bytes = Vec::from(b"# coding: latin-1\n");
        bytes.push(0xff);
        let policy = detect_encoding(&bytes);
        assert_eq!(policy, EncodingPolicy::Unsupported);
    }

    #[test]
    fn inline_comment_keeps_exact_pin() {
        let line = prepare_requirement_line("evil==1.2.3  # pinned release");
        let req = parse_requirement(&line).unwrap();
        assert_eq!(req.name, "evil");
        assert_eq!(req.exact_version.as_deref(), Some("1.2.3"));
    }

    #[test]
    fn url_hash_fragment_is_not_a_comment() {
        let line = prepare_requirement_line("pkg @ git+https://example.com/pkg.git#egg=pkg");
        assert!(line.contains("#egg=pkg"));
    }

    #[test]
    fn continued_hash_option_is_stripped() {
        let joined = logical_lines("evil==1.2.3 \\\n    --hash=sha256:deadbeef\n").join("");
        let line = prepare_requirement_line(&joined);
        let req = parse_requirement(&line).unwrap();
        assert_eq!(req.name, "evil");
        assert_eq!(req.exact_version.as_deref(), Some("1.2.3"));
        assert!(!line.contains("deadbeef"));
    }

    #[test]
    fn constraint_only_nested_requirement_include_is_not_evidence() {
        let base = std::env::temp_dir().join(format!("req-cn-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        let main = base.join("requirements.txt");
        let constraints = base.join("requirements-constraints.txt");
        let nested = base.join("requirements-nested.txt");
        std::fs::write(&main, "-c requirements-constraints.txt\n").unwrap();
        std::fs::write(&constraints, "-r requirements-nested.txt\n").unwrap();
        std::fs::write(&nested, "evil==1.2.3\n").unwrap();
        let results = scan_in(&[main.clone(), constraints.clone(), nested.clone()], &base);
        let findings: usize = results.iter().map(|(_, s)| s.findings.len()).sum();
        let evidence: usize = results.iter().map(|(_, s)| s.evidence.len()).sum();
        assert_eq!(findings, 0);
        assert_eq!(evidence, 0);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn many_discovered_files_are_not_capped_as_includes() {
        let base = std::env::temp_dir().join(format!("req-many-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        let mut paths = Vec::new();
        for i in 0..INCLUDE_MAX_FILES + 5 {
            let path = base.join(format!("requirements-{i}.txt"));
            std::fs::write(&path, "benign>=1\n").unwrap();
            paths.push(path);
        }
        let results = scan_in(&paths, &base);
        assert_eq!(results.len(), INCLUDE_MAX_FILES + 5);
        assert!(
            results
                .iter()
                .all(|(_, s)| s.status == ArtifactStatus::Inspected)
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}
