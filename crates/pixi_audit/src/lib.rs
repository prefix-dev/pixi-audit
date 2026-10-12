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
    AuditError, BASILISK_URL_ENV_VAR, BasiliskClient, DEFAULT_BASILISK_URL, DEFAULT_OSV_URL,
    OSV_URL_ENV_VAR, OsvDevClient, TOKEN_ENV_VAR, TOKEN_LENGTH, TOKEN_PREFIX,
    looks_like_basilisk_token,
};
#[cfg(feature = "lock")]
pub use lock::{LockFileAuditError, audit_lock_file, collect_packages};
pub use osv_protocol as types;
/// Re-exported so consumers can name `LockFile` without their own dependency.
#[cfg(feature = "lock")]
pub use rattler_lock;
pub use report::{
    AuditPackage, AuditReport, AuditSummary, CondaForgeBuild, FixAvailability, IgnoreMode,
    IgnoreRule, IgnoreScope, IgnoreSpec, InvalidIgnoreScope, InvalidPackageName, Match,
    MatchConfidence, MatchedIdentity, MatchedIdentityKind, OtherEcosystemFix, PackageEcosystem,
    PackageId, PackageName, PackageVersion, ParsePackageVersionError, ParseSeverityRatingError,
    SeverityRating, SortKey, UpstreamRelease,
};
pub use threat::{RiskScore, ThreatDataStatus, ThreatSourceStatus, ThreatSources};
pub use threat_feeds::{
    DEFAULT_EPSS_BASE_URL, DEFAULT_KEV_URL, EPSS_BASE_URL_ENV_VAR, EpssClient, EpssScore,
    KEV_URL_ENV_VAR, KevCatalog, KevClient, KevEntry, RansomwareCampaignUse, ThreatFeedError,
};
