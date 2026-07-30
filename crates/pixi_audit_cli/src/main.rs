//! `pixi-audit` — a pixi extension (`pixi audit`) that audits a `pixi.lock`
//! file for known vulnerabilities against an OSV-compatible API.

use std::path::PathBuf;

use clap::Parser;

/// Audit a pixi.lock file for known vulnerabilities.
///
/// Exit codes: 0 = no vulnerabilities, 1 = vulnerabilities found,
/// 2 = execution error.
#[derive(Debug, Parser)]
#[command(name = "pixi-audit", version)]
struct Cli {
    /// Path to the pixi.lock file to audit
    lockfile: PathBuf,

    /// Audit only this environment (repeatable)
    #[arg(long = "environment", value_name = "ENV")]
    environments: Vec<String>,

    /// Audit only this platform (repeatable)
    #[arg(long = "platform", value_name = "PLATFORM")]
    platforms: Vec<String>,

    /// Vulnerability id or alias to ignore, case-insensitive (repeatable).
    /// Ignored findings still appear in the report's ignored section.
    #[arg(long = "ignore", value_name = "ID")]
    ignore: Vec<String>,

    /// Emit the report as pretty-printed JSON on stdout
    #[arg(long)]
    json: bool,
}

fn main() {
    let cli = Cli::parse();
    // Wired up in a later task.
    let _ = cli;
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn lockfile_is_required() {
        assert!(Cli::try_parse_from(["pixi-audit"]).is_err());
    }

    #[test]
    fn repeatable_flags_accumulate() {
        let cli = Cli::try_parse_from([
            "pixi-audit",
            "pixi.lock",
            "--environment",
            "default",
            "--environment",
            "prod",
            "--platform",
            "linux-64",
            "--ignore",
            "CVE-2026-1234",
            "--json",
        ])
        .unwrap();
        assert_eq!(cli.lockfile, PathBuf::from("pixi.lock"));
        assert_eq!(cli.environments, vec!["default", "prod"]);
        assert_eq!(cli.platforms, vec!["linux-64"]);
        assert_eq!(cli.ignore, vec!["CVE-2026-1234"]);
        assert!(cli.json);
    }
}
