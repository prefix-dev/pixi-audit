//! Audit locked packages for known vulnerabilities against an
//! OSV-compatible vulnerability API (basilisk).

pub mod client;
mod cvss_v2;
#[cfg(feature = "lock")]
pub mod lock;
pub mod report;

pub use client::{AuditError, BASE_URL_ENV_VAR, BasiliskClient, DEFAULT_BASE_URL};
#[cfg(feature = "lock")]
pub use lock::{LockFileAuditError, audit_lock_file, collect_packages};
pub use osv_protocol as types;
pub use osv_protocol::*;
/// Re-exported so consumers can name `LockFile` without their own dependency.
#[cfg(feature = "lock")]
pub use rattler_lock;
pub use report::{
    AuditPackage, AuditReport, AuditSummary, Finding, IgnoreReason, IgnoreSpec, PackageEcosystem,
    SeverityBand, UncheckedPackage, audit,
};
