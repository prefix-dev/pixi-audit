use std::collections::{BTreeSet, HashMap};

use crate::report::Finding;

/// Coalesces documents by id or alias within one queried package.
/// An alias may connect two groups only after both have been seen.
pub(super) struct FindingGroups {
    groups: Vec<Finding>,
    by_id: HashMap<String, usize>,
}

impl FindingGroups {
    pub(super) fn with_capacity(capacity: usize) -> Self {
        Self {
            groups: Vec::with_capacity(capacity),
            by_id: HashMap::new(),
        }
    }

    pub(super) fn push(&mut self, finding: Finding) {
        let matches: BTreeSet<usize> = finding
            .ids()
            .filter_map(|id| self.by_id.get(&id.to_ascii_lowercase()).copied())
            .collect();
        let index = if let Some(&index) = matches.first() {
            self.groups[index].merge_from(finding);
            // Removing from the end leaves the surviving group at `index`.
            for other in matches.into_iter().skip(1).rev() {
                let previous = self.groups.swap_remove(other);
                if other < self.groups.len() {
                    for id in self.groups[other].ids() {
                        self.by_id.insert(id.to_ascii_lowercase(), other);
                    }
                }
                self.groups[index].merge_from(previous);
            }
            index
        } else {
            let index = self.groups.len();
            self.groups.push(finding);
            index
        };
        for id in self.groups[index].ids() {
            self.by_id.insert(id.to_ascii_lowercase(), index);
        }
    }

    pub(super) fn into_findings(self) -> impl Iterator<Item = Finding> {
        self.groups.into_iter()
    }
}

impl Finding {
    fn ids(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.id.as_str()).chain(self.aliases.iter().map(String::as_str))
    }

    /// Merge another finding for the same package before suppression and threat enrichment.
    fn merge_from(&mut self, other: Finding) {
        self.aliases.push(other.id);
        self.aliases.extend(other.aliases);
        self.aliases.retain(|id| !id.eq_ignore_ascii_case(&self.id));
        self.aliases.sort_unstable();
        self.aliases.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
        self.severity = self.severity.max(other.severity);
        self.cvss_base_score = match (self.cvss_base_score, other.cvss_base_score) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        };
        for fixed in other.fixed_versions {
            if !self.fixed_versions.contains(&fixed) {
                self.fixed_versions.push(fixed);
            }
        }
        for fixed in other.upstream_fixes {
            if !self.upstream_fixes.contains(&fixed) {
                self.upstream_fixes.push(fixed);
            }
        }
        self.applicability = self.applicability.min(other.applicability);
        if self.matched_identity != other.matched_identity {
            self.matched_identity = None;
        }
        self.summary = self.summary.take().or(other.summary);
        self.url = self.url.take().or(other.url);
    }
}
