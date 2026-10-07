//! Audit locked packages for known vulnerabilities against an
//! OSV-compatible vulnerability API (basilisk).

mod advisory;
mod audit;
pub mod client;
mod cvss_v2;
#[cfg(feature = "lock")]
pub mod lock;
pub mod report;
#[cfg(test)]
mod test_support;
pub mod threat;

pub use client::{
    AuditError, BASE_URL_ENV_VAR, BasiliskClient, DEFAULT_BASE_URL, DEFAULT_EPSS_BASE_URL,
    DEFAULT_KEV_URL, DEFAULT_PYPI_BASE_URL, EPSS_BASE_URL_ENV_VAR, EpssClient, KEV_URL_ENV_VAR,
    KevCatalog, KevClient, PYPI_BASE_URL_ENV_VAR, PypiAuditClient, TOKEN_ENV_VAR, TOKEN_LENGTH,
    TOKEN_PREFIX, ThreatFeedError, looks_like_basilisk_token,
};
#[cfg(feature = "lock")]
pub use lock::{LockFileAuditError, audit_lock_file, collect_packages};
pub use osv_protocol as types;
pub use osv_protocol::*;
/// Re-exported so consumers can name `LockFile` without their own dependency.
#[cfg(feature = "lock")]
pub use rattler_lock;
pub use report::{
    AuditPackage, AuditReport, AuditSummary, CondaPublication, Finding, FixStatus, IgnoreReason,
    IgnoreScope, IgnoreSpec, InvalidPackageName, MatchApplicability, MatchedIdentity,
    MatchedIdentityKind, PackageEcosystem, PackageId, PackageIgnore, PackageName, PackageVersion,
    ParsePackageVersionError, ParseSeverityBandError, SeverityBand, SortStrategy, UpstreamFix,
    UpstreamOrigin, audit,
};
pub use threat::{
    EpssScore, KnownExploited, RansomwareCampaignUse, RiskScore, ThreatDataStatus,
    ThreatSourceStatus, ThreatSources,
};
