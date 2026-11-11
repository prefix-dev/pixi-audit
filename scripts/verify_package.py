"""Smoke-test the pixi-audit Conda package built into a directory.

Checks that the directory holds exactly one package, that its file name carries
the expected Conda version, and that the binary inside reports the expected CLI
version. An empty expected version skips that check, which pull request builds
use because their versions are not known up front.

Exits with status 1 and a message on stderr when a check fails.
"""

import argparse
import subprocess
import sys
from pathlib import Path


def fail(message: str) -> None:
    print(message, file=sys.stderr)
    sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("dist", type=Path, help="Directory holding the built package.")
    parser.add_argument("--package-version", default="", help="Expected Conda package version.")
    parser.add_argument("--cli-version", default="", help="Expected `pixi-audit --version` version.")
    args = parser.parse_args()

    packages = sorted(args.dist.glob("*.conda"))
    if len(packages) != 1:
        fail(f"Expected one package in {args.dist}, found {len(packages)}.")
    package = packages[0]

    if args.package_version and not package.name.startswith(f"pixi-audit-{args.package_version}-"):
        fail(f"Package {package.name} does not have version {args.package_version}.")

    result = subprocess.run(
        ["pixi", "exec", "--spec", str(package), "pixi-audit", "--version"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        fail(f"Running pixi-audit from {package.name} failed:\n{result.stderr}")
    actual_version = result.stdout.strip()

    if args.cli_version and actual_version != f"pixi-audit {args.cli_version}":
        fail(f"Binary version {actual_version} does not match {args.cli_version}.")

    print(f"Built and tested {package} ({actual_version})")


if __name__ == "__main__":
    main()
