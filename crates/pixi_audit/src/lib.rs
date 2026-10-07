//! Audit locked packages for known vulnerabilities against an
//! OSV-compatible vulnerability API (basilisk).

mod advisory;
mod audit;
pub mod client;
pub mod config;
mod cvss_v2;
#[cfg(feature = "lock")]
pub mod lock;
pub mod report;
#[cfg(test)]
mod test_support;
pub mod threat;

pub use audit::audit;
pub use client::{
    AuditError, BASE_URL_ENV_VAR, BasiliskClient, DEFAULT_BASE_URL, DEFAULT_PYPI_BASE_URL,
    PYPI_BASE_URL_ENV_VAR, PypiAuditClient,
};
#[cfg(feature = "lock")]
pub use lock::{LockFileAuditError, audit_lock_file, collect_packages};
pub use osv_protocol as types;
/// Re-exported so consumers can name `LockFile` without their own dependency.
#[cfg(feature = "lock")]
pub use rattler_lock;
pub use report::{
    AuditPackage, AuditReport, AuditSummary, CondaPublication, Finding, FixStatus, IgnoreReason,
    IgnoreRule, IgnoreScope, IgnoreSpec, InvalidIgnoreScope, InvalidPackageName,
    MatchApplicability, MatchedIdentity, MatchedIdentityKind, PackageEcosystem, PackageId,
    PackageName, PackageVersion, ParsePackageVersionError, ParseSeverityBandError, SeverityBand,
    SortStrategy, UpstreamFix, UpstreamOrigin,
};
pub use threat::{RiskScore, ThreatDataStatus, ThreatSourceStatus, ThreatSources};
pub use threat_feeds::{
    DEFAULT_EPSS_BASE_URL, DEFAULT_KEV_URL, EPSS_BASE_URL_ENV_VAR, EpssClient, EpssScore,
    KEV_URL_ENV_VAR, KevCatalog, KevClient, KnownExploited, RansomwareCampaignUse, ThreatFeedError,
};
