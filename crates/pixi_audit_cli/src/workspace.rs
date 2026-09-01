//! Resolves the lockfile and manifest that govern an audit run.

use std::path::PathBuf;

use miette::{Context, IntoDiagnostic};

use crate::config;

/// The lockfile to audit and the workspace manifest that governs it.
pub struct ResolvedTargets {
    pub lockfile: PathBuf,
    /// `None` when an explicit lockfile has no manifest beside it.
    pub manifest: Option<PathBuf>,
}

/// An explicit lockfile is used as-is (manifest = its sibling, if any).
/// Otherwise the workspace is discovered by walking up from the cwd.
pub fn resolve_targets(cli_lockfile: Option<PathBuf>) -> miette::Result<ResolvedTargets> {
    match cli_lockfile {
        Some(lockfile) => {
            let manifest = match lockfile
                .canonicalize()
                .ok()
                .and_then(|path| path.parent().map(std::path::Path::to_path_buf))
            {
                Some(directory) => config::find_manifest_in(&directory)?,
                None => None,
            };
            Ok(ResolvedTargets { lockfile, manifest })
        }
        None => {
            let cwd = std::env::current_dir()
                .into_diagnostic()
                .wrap_err("cannot determine the current directory")?;
            let manifest = config::discover_workspace(&cwd)?.ok_or_else(|| {
                miette::miette!(
                    "no pixi workspace found; pass a lockfile path or run inside a pixi workspace"
                )
            })?;
            let root = manifest.parent().expect("manifest has a directory");
            let lockfile = root.join("pixi.lock");
            if !lockfile.is_file() {
                return Err(miette::miette!(
                    "workspace at '{}' has no pixi.lock; run `pixi lock` first",
                    root.display()
                ));
            }
            Ok(ResolvedTargets {
                lockfile,
                manifest: Some(manifest),
            })
        }
    }
}
