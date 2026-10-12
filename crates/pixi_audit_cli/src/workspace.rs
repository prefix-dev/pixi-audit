//! Resolves audit targets and handles workspace manifest reads and edits.

use std::path::{Path, PathBuf};

use miette::{Context, IntoDiagnostic, miette};
use toml_edit::{DocumentMut, Item, TableLike};

/// A parsed manifest that retains formatting and comments when edited.
pub struct Manifest {
    pub path: PathBuf,
    pub document: DocumentMut,
}

impl Manifest {
    /// Load the editable TOML document, reporting its path on IO or parse errors.
    pub fn load(path: &Path) -> miette::Result<Self> {
        let content = std::fs::read_to_string(path)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to read manifest '{}'", path.display()))?;
        let document = content
            .parse::<DocumentMut>()
            .into_diagnostic()
            .wrap_err_with(|| format!("'{}' is not valid TOML", path.display()))?;
        Ok(Self {
            path: path.to_owned(),
            document,
        })
    }

    /// Write back to the original path. Call only when an edit changed the document.
    pub fn save(&self) -> miette::Result<()> {
        std::fs::write(&self.path, self.document.to_string())
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to update manifest '{}'", self.path.display()))
    }

    /// Pixi dependencies live at the root in pixi.toml and under
    /// `[tool.pixi]` in pyproject.toml; never edit Python project metadata.
    pub fn pixi_table_mut(&mut self) -> miette::Result<&mut dyn TableLike> {
        if self.path.file_name().and_then(|name| name.to_str()) == Some("pyproject.toml") {
            self.document
                .get_mut("tool")
                .and_then(Item::as_table_like_mut)
                .and_then(|tool| tool.get_mut("pixi"))
                .and_then(Item::as_table_like_mut)
                .ok_or_else(|| miette!("'{}' has no [tool.pixi] table", self.path.display()))
        } else {
            Ok(self.document.as_table_mut())
        }
    }
}

/// Find the workspace manifest in one directory, preferring pixi.toml.
/// Invalid pyproject.toml is an error, not a reason to skip this directory.
fn find_manifest_in(dir: &Path) -> miette::Result<Option<PathBuf>> {
    let pixi = dir.join("pixi.toml");
    if pixi.is_file() {
        return Ok(Some(pixi));
    }
    let pyproject = dir.join("pyproject.toml");
    if pyproject.is_file() {
        let manifest = Manifest::load(&pyproject)?;
        if manifest
            .document
            .get("tool")
            .and_then(|tool| tool.get("pixi"))
            .is_some()
        {
            return Ok(Some(pyproject));
        }
    }
    Ok(None)
}

/// Walk up from `start` to the nearest workspace manifest.
pub fn discover_workspace(start: &Path) -> miette::Result<Option<PathBuf>> {
    for dir in start.ancestors() {
        if let Some(manifest) = find_manifest_in(dir)? {
            return Ok(Some(manifest));
        }
    }
    Ok(None)
}

/// The lock file to audit and the workspace manifest that governs it.
pub struct ResolvedTargets {
    pub lock_file: PathBuf,
    /// `None` when an explicit lock file has no manifest beside it.
    pub manifest: Option<PathBuf>,
}

/// An explicit lock file is used as-is (manifest = its sibling, if any).
/// Otherwise the workspace is discovered by walking up from the cwd.
pub fn resolve_targets(cli_lock_file: Option<PathBuf>) -> miette::Result<ResolvedTargets> {
    match cli_lock_file {
        Some(lock_file) => {
            let manifest = match lock_file
                .canonicalize()
                .ok()
                .and_then(|path| path.parent().map(std::path::Path::to_path_buf))
            {
                Some(directory) => find_manifest_in(&directory)?,
                None => None,
            };
            Ok(ResolvedTargets {
                lock_file,
                manifest,
            })
        }
        None => {
            let cwd = std::env::current_dir()
                .into_diagnostic()
                .wrap_err("cannot determine the current directory")?;
            let manifest = discover_workspace(&cwd)?.ok_or_else(|| {
                miette::miette!(
                    "no pixi workspace found; pass a lock file path or run inside a pixi workspace"
                )
            })?;
            let root = manifest.parent().expect("manifest has a directory");
            let lock_file = root.join("pixi.lock");
            if !lock_file.is_file() {
                return Err(miette::miette!(
                    "workspace at '{}' has no pixi.lock; run `pixi lock` first",
                    root.display()
                ));
            }
            Ok(ResolvedTargets {
                lock_file,
                manifest: Some(manifest),
            })
        }
    }
}

#[cfg(test)]
mod tests;
