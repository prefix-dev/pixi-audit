//! Obtaining the short-lived Basilisk token from the user's Pixi login.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use miette::Diagnostic;
use pixi_audit::DEFAULT_BASE_URL;
use reqwest::header::HeaderValue;
use thiserror::Error;
use tokio::process::Command;
use url::{Host, Url};

const PIXI_EXE_ENV_VAR: &str = "PIXI_EXE";
const TOKEN_HOST: &str = "prefix.dev";
const TOKEN_COMMAND_TIMEOUT: Duration = Duration::from_secs(10);

/// Obtains a short-lived token from the user's existing Pixi OAuth login.
///
/// Keeping this provider in the executable means the reusable `pixi_audit`
/// crate never launches Pixi implicitly.
pub(crate) struct PixiTokenProvider {
    executable: PathBuf,
    timeout: Duration,
}

impl PixiTokenProvider {
    pub(crate) fn new(executable: PathBuf) -> Self {
        Self {
            executable,
            timeout: TOKEN_COMMAND_TIMEOUT,
        }
    }

    #[cfg(test)]
    fn with_timeout(executable: PathBuf, timeout: Duration) -> Self {
        Self {
            executable,
            timeout,
        }
    }

    pub(crate) async fn bearer_header(&self) -> miette::Result<HeaderValue> {
        let mut command = Command::new(&self.executable);
        command
            .args(["auth", "token", TOKEN_HOST])
            // Dropping the timed-out output future kills the child instead of
            // leaving a token-producing process or its captured pipes alive.
            .kill_on_drop(true);
        let output = tokio::time::timeout(self.timeout, command.output())
            .await
            .map_err(|_| TokenError::CommandTimedOut {
                executable: self.executable.clone(),
                timeout: self.timeout,
            })?
            .map_err(|source| TokenError::CommandStart {
                executable: self.executable.clone(),
                source,
            })?;

        if !output.status.success() {
            return Err(TokenError::CommandFailed {
                executable: self.executable.clone(),
                status: output.status.to_string(),
            }
            .into());
        }

        // Pixi writes only the token to stdout. Never include stdout or stderr
        // in an error: either stream could contain credential material.
        let stdout = std::str::from_utf8(&output.stdout).map_err(|_| TokenError::InvalidOutput)?;
        let token = stdout.trim_end_matches(['\r', '\n']);
        if token.is_empty() || token.chars().any(char::is_whitespace) {
            return Err(TokenError::InvalidOutput.into());
        }

        let mut value = HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| TokenError::InvalidOutput)?;
        value.set_sensitive(true);
        Ok(value)
    }
}

/// Whether it is safe to send a prefix.dev credential to this base URL.
///
/// Production must match the default URL exactly. HTTP and HTTPS loopback
/// hosts are also allowed for local development and tests. All other custom
/// services remain anonymous.
pub(crate) fn should_attach_token(base_url: &Url) -> bool {
    let default = Url::parse(DEFAULT_BASE_URL).expect("DEFAULT_BASE_URL is valid");
    if base_url == &default {
        return true;
    }

    if !matches!(base_url.scheme(), "http" | "https") {
        return false;
    }

    match base_url.host() {
        Some(Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    }
}

/// Resolves Pixi once, preferring `PIXI_EXE` and otherwise searching `PATH`.
pub(crate) fn resolve_pixi_executable() -> miette::Result<PathBuf> {
    resolve_pixi_executable_from(std::env::var_os(PIXI_EXE_ENV_VAR), std::env::var_os("PATH"))
        .ok_or_else(|| TokenError::ExecutableNotFound.into())
}

fn resolve_pixi_executable_from(
    configured: Option<OsString>,
    path: Option<OsString>,
) -> Option<PathBuf> {
    if let Some(configured) = configured {
        return Some(PathBuf::from(configured));
    }

    let path = path?;
    std::env::split_paths(&path)
        .flat_map(|directory| pixi_candidates(&directory))
        .find(|candidate| is_executable(candidate))
}

#[cfg(windows)]
fn pixi_candidates(directory: &Path) -> Vec<PathBuf> {
    ["pixi.exe", "pixi.cmd", "pixi.bat", "pixi.com", "pixi"]
        .into_iter()
        .map(|name| directory.join(name))
        .collect()
}

#[cfg(not(windows))]
fn pixi_candidates(directory: &Path) -> Vec<PathBuf> {
    vec![directory.join("pixi")]
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    path.metadata()
        .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

#[derive(Debug, Error, Diagnostic)]
enum TokenError {
    #[error("could not find a Pixi executable using PIXI_EXE or PATH")]
    #[diagnostic(help(
        "Upgrade to a Pixi release containing PFX-1798 (with `auth token` and `basilisk:query`) and ensure it is on PATH, or set PIXI_EXE to the Pixi executable. Then run `pixi auth logout prefix.dev` followed by `pixi auth login prefix.dev` and retry."
    ))]
    ExecutableNotFound,

    #[error("could not run '{} auth token {TOKEN_HOST}'", .executable.display())]
    #[diagnostic(help(
        "Upgrade to a Pixi release containing PFX-1798 (with `auth token` and `basilisk:query`) and ensure it is on PATH, or set PIXI_EXE to the Pixi executable. Then run `pixi auth logout prefix.dev` followed by `pixi auth login prefix.dev` and retry."
    ))]
    CommandStart {
        executable: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error(
        "'{} auth token {TOKEN_HOST}' failed ({status})",
        .executable.display()
    )]
    #[diagnostic(help(
        "Upgrade to a Pixi release containing PFX-1798 (with `auth token` and `basilisk:query`) first, then run `pixi auth logout prefix.dev` followed by `pixi auth login prefix.dev` and retry."
    ))]
    CommandFailed { executable: PathBuf, status: String },

    #[error(
        "'{} auth token {TOKEN_HOST}' timed out after {} seconds",
        .executable.display(),
        .timeout.as_secs()
    )]
    #[diagnostic(help(
        "Upgrade to a Pixi release containing PFX-1798 (with `auth token` and `basilisk:query`) first, then run `pixi auth logout prefix.dev` followed by `pixi auth login prefix.dev` and retry."
    ))]
    CommandTimedOut {
        executable: PathBuf,
        timeout: Duration,
    },

    #[error("'pixi auth token {TOKEN_HOST}' did not return one non-empty token")]
    #[diagnostic(help(
        "Upgrade to a Pixi release containing PFX-1798 (with `auth token` and `basilisk:query`) first, then run `pixi auth logout prefix.dev` followed by `pixi auth login prefix.dev` and retry."
    ))]
    InvalidOutput,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_is_limited_to_default_and_loopback_urls() {
        for allowed in [
            DEFAULT_BASE_URL,
            "http://localhost:8080/api/",
            "https://127.0.0.1:4443/",
            "http://[::1]:8080/",
        ] {
            assert!(
                should_attach_token(&Url::parse(allowed).unwrap()),
                "expected token for {allowed}"
            );
        }

        for denied in [
            "http://api.basilisk.prefix.dev/",
            "https://api.basilisk.prefix.dev/other",
            "https://api.basilisk.prefix.dev/?query=1",
            "https://audit.example.com/",
            "http://0.0.0.0:8080/",
        ] {
            assert!(
                !should_attach_token(&Url::parse(denied).unwrap()),
                "unexpected token for {denied}"
            );
        }
    }

    #[test]
    fn executable_prefers_pixi_exe_and_falls_back_to_path() {
        let dir = tempfile::tempdir().unwrap();
        let path_pixi = dir
            .path()
            .join(if cfg!(windows) { "pixi.exe" } else { "pixi" });
        std::fs::write(&path_pixi, "").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path_pixi, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        assert_eq!(
            resolve_pixi_executable_from(
                Some(OsString::from("/custom/pixi")),
                Some(dir.path().as_os_str().to_owned())
            ),
            Some(PathBuf::from("/custom/pixi"))
        );
        assert_eq!(
            resolve_pixi_executable_from(None, Some(dir.path().as_os_str().to_owned())),
            Some(path_pixi)
        );
        assert_eq!(resolve_pixi_executable_from(None, None), None);
    }

    #[cfg(unix)]
    fn script(contents: &str) -> (tempfile::TempDir, PathBuf) {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pixi");
        std::fs::write(&path, contents).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        (dir, path)
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn invokes_exact_token_command_and_trims_line_endings() {
        let (dir, executable) = script(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$(dirname \"$0\")/args\"\nprintf 'short-lived-token\\r\\n'\n",
        );
        let header = PixiTokenProvider::new(executable)
            .bearer_header()
            .await
            .unwrap();

        assert_eq!(header.to_str().unwrap(), "Bearer short-lived-token");
        assert!(header.is_sensitive());
        assert_eq!(
            std::fs::read_to_string(dir.path().join("args")).unwrap(),
            "auth\ntoken\nprefix.dev\n"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rejects_empty_and_multiple_token_output() {
        for stdout in ["", "\\n", "first\\nsecond\\n", "token with spaces\\n"] {
            let script_body = format!("#!/bin/sh\nprintf '{stdout}'\n");
            let (_dir, executable) = script(&script_body);
            let error = PixiTokenProvider::new(executable)
                .bearer_header()
                .await
                .unwrap_err();
            assert!(
                format!("{error:?}").contains("did not return one non-empty token"),
                "unexpected error: {error:?}"
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn command_failure_is_actionable_and_keeps_streams_secret() {
        const SECRET: &str = "must-not-appear-in-errors";
        let (_dir, executable) = script(&format!(
            "#!/bin/sh\nprintf '{SECRET}'\nprintf '{SECRET}' >&2\nexit 9\n"
        ));
        let error = PixiTokenProvider::new(executable)
            .bearer_header()
            .await
            .unwrap_err();
        let rendered = format!("{error:?}");

        assert!(rendered.contains("PFX-1798"));
        assert!(rendered.contains("basilisk:query"));
        assert!(rendered.contains("pixi auth logout prefix.dev"));
        assert!(rendered.contains("pixi auth login prefix.dev"));
        assert!(
            rendered.find("pixi auth logout").unwrap() < rendered.find("pixi auth login").unwrap()
        );
        assert!(!rendered.contains(SECRET), "secret leaked in: {rendered}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn token_command_times_out_without_surfacing_streams() {
        const SECRET: &str = "timeout-stream-secret";
        let (_dir, executable) = script(&format!(
            "#!/bin/sh\nprintf '{SECRET}'\nprintf '{SECRET}' >&2\nsleep 5\n"
        ));
        let error = PixiTokenProvider::with_timeout(executable, Duration::from_millis(100))
            .bearer_header()
            .await
            .unwrap_err();
        let rendered = format!("{error:?}");

        assert!(
            rendered.contains("timed out"),
            "unexpected error: {rendered}"
        );
        assert!(!rendered.contains(SECRET), "secret leaked in: {rendered}");
    }

    #[tokio::test]
    async fn missing_configured_executable_error_is_actionable() {
        let error = PixiTokenProvider::new(PathBuf::from("definitely-no-such-pixi-executable"))
            .bearer_header()
            .await
            .unwrap_err();
        let rendered = format!("{error:?}");

        assert!(rendered.contains("PFX-1798"));
        assert!(rendered.contains("PIXI_EXE"));
        assert!(rendered.contains("pixi auth logout prefix.dev"));
        assert!(rendered.contains("pixi auth login prefix.dev"));
    }
}
