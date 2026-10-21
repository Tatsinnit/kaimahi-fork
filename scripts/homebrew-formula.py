#!/usr/bin/env python3
"""Validate release versions and checksum manifests.

GoReleaser (.goreleaser.yaml) renders the actual Homebrew formula now; this
script checks the version before anything is built, then verifies GoReleaser's
checksum manifest. A manifest names exactly the four Unix assets (every release
published so far) or those four plus both native Windows `.exe` assets; the
release build passes --require-windows so a new release must name all six.
The Homebrew formula only ever covers the four Unix assets. The rendering
functions remain available for that validation and their focused self-test;
their output is not the formula published by the release workflow.

Run:  python3 scripts/homebrew-formula.py --check-version v0.3.0
      python3 scripts/homebrew-formula.py v0.3.0 checksums.txt >/dev/null
      python3 scripts/homebrew-formula.py v0.3.0 checksums.txt --require-windows
      python3 scripts/homebrew-formula.py --selftest
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path


ASSETS = (
    ("darwin", "arm64", "macos", "arm"),
    ("darwin", "amd64", "macos", "intel"),
    ("linux", "arm64", "linux", "arm"),
    ("linux", "amd64", "linux", "intel"),
)
UNIX_ASSET_NAMES = frozenset(f"kmx-{os_name}-{arch}" for os_name, arch, _, _ in ASSETS)
# GoReleaser's `binary` archive format appends the build's extension to
# archives.name_template, and the Go builder's extension for windows targets
# is `.exe` (goreleaser v2.18.2 internal/pipe/archive skip, build extFor).
WINDOWS_ASSET_NAMES = frozenset(
    f"kmx-windows-{arch}.exe" for arch in ("amd64", "arm64")
)
ASSET_NAMES = UNIX_ASSET_NAMES | WINDOWS_ASSET_NAMES
SEMVER_NUMBER = r"(?:0|[1-9][0-9]*)"
SEMVER_PRERELEASE = (
    r"(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
)
VERSION_RE = re.compile(
    rf"^v{SEMVER_NUMBER}\.{SEMVER_NUMBER}\.{SEMVER_NUMBER}"
    rf"(?:-{SEMVER_PRERELEASE}(?:\.{SEMVER_PRERELEASE})*)?$"
)
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
BASE_RE = re.compile(r"^(?:https?|file)://[A-Za-z0-9._~:/%+-]+$")


def release_version(tag: str) -> str:
    """Return a tag's Homebrew version after strict SemVer validation."""
    if not VERSION_RE.fullmatch(tag):
        raise ValueError(
            f"version {tag!r} is not v<major>.<minor>.<patch>[-prerelease]"
        )
    return tag[1:]


def parse_checksums(text: str, require_windows: bool = False) -> dict[str, str]:
    """Read exactly one SHA-256 for each published kmx binary asset.

    The Unix assets are always required. Windows assets are all-or-nothing so
    a manifest can never publish one Windows architecture by accident, and
    require_windows makes them mandatory for newly built releases.
    """
    checksums: dict[str, str] = {}
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        fields = line.split()
        if len(fields) != 2 or not SHA256_RE.fullmatch(fields[0]):
            raise ValueError(f"checksums line {line_number} is not '<sha256> <asset>'")
        digest, name = fields
        if name not in ASSET_NAMES:
            raise ValueError(f"checksums line {line_number} names unexpected asset {name!r}")
        if name in checksums:
            raise ValueError(f"checksums contains {name!r} more than once")
        checksums[name] = digest.lower()
    expected = set(UNIX_ASSET_NAMES)
    if require_windows or WINDOWS_ASSET_NAMES & checksums.keys():
        expected |= WINDOWS_ASSET_NAMES
    missing = sorted(expected - checksums.keys())
    if missing:
        raise ValueError("checksums is missing " + ", ".join(missing))
    return checksums


def unix_checksums(checksums: dict[str, str]) -> dict[str, str]:
    """Select the assets the Homebrew formula installs (never Windows)."""
    return {name: checksums[name] for name in UNIX_ASSET_NAMES if name in checksums}


def validate_asset_base(asset_base: str) -> str:
    """Accept a URL base that is safe to embed in a Ruby string literal."""
    asset_base = asset_base.rstrip("/")
    if not BASE_RE.fullmatch(asset_base):
        raise ValueError("asset base must be one http(s) or file URL without quoting")
    return asset_base


def render_formula(tag: str, checksums: dict[str, str], asset_base: str) -> str:
    """Render one deterministic Homebrew formula from validated release data."""
    version = release_version(tag)
    asset_base = validate_asset_base(asset_base)
    default_asset_base = (
        "https://github.com/kaimahi-agents/kaimahi/releases/download/" + tag
    )
    missing = sorted(UNIX_ASSET_NAMES - checksums.keys())
    extra = sorted(checksums.keys() - UNIX_ASSET_NAMES)
    if missing or extra:
        detail = []
        if missing:
            detail.append("missing " + ", ".join(missing))
        if extra:
            detail.append("unexpected " + ", ".join(extra))
        raise ValueError("invalid checksum set: " + "; ".join(detail))
    for name, digest in checksums.items():
        if not SHA256_RE.fullmatch(digest):
            raise ValueError(f"checksum for {name!r} is not a SHA-256")

    lines = [
        "# typed: false",
        "# frozen_string_literal: true",
        "",
        "# Kaimahi's kmx command-line interface.",
        "class Kmx < Formula",
        '  desc "Agent Builder CLI for Kubernetes"',
        '  homepage "https://github.com/kaimahi-agents/kaimahi"',
    ]
    # Stable production URLs let Homebrew infer the version, and strict audit
    # rejects restating it. Prereleases confuse URL inference, while a custom
    # base may carry no version at all, so those cases must be explicit.
    if "-" in tag or asset_base != default_asset_base:
        lines.append(f'  version "{version}"')
    lines.extend(['  license "MIT"', ""])
    current_os = None
    for os_name, arch, formula_os, formula_arch in ASSETS:
        if formula_os != current_os:
            if current_os is not None:
                lines.extend(["  end", ""])
            lines.append(f"  on_{formula_os} do")
            current_os = formula_os
        name = f"kmx-{os_name}-{arch}"
        lines.extend(
            [
                f"    on_{formula_arch} do",
                f'      url "{asset_base}/{name}", using: :nounzip',
                f'      sha256 "{checksums[name]}"',
                "    end",
            ]
        )
        if formula_arch == "arm":
            lines.append("")
    lines.extend(
        [
            "  end",
            "",
            "  def install",
            '    bin.install Dir["kmx-*"].first => "kmx"',
            "  end",
            "",
            "  test do",
            '    assert_equal "kmx v#{version} (release build)",',
            '                 shell_output("#{bin}/kmx version").lines.first.chomp',
            '    assert_match "Usage:",',
            '                 shell_output("#{bin}/kmx create --help")',
            "  end",
            "end",
            "",
        ]
    )
    return "\n".join(lines)


def write_formula(path: Path, formula: str) -> None:
    """Atomically replace the requested formula output file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".tmp.{os.getpid()}")
    try:
        temporary.write_text(formula)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def selftest() -> int:
    """Exercise accepted output and every fail-closed input boundary."""
    failed = 0
    fixture = "\n".join(
        f"{index:064x}  kmx-{os_name}-{arch}"
        for index, (os_name, arch, _, _) in enumerate(ASSETS, 1)
    )

    def check(name: str, condition: bool) -> None:
        nonlocal failed
        print(("ok  " if condition else "FAIL") + f" {name}")
        failed += not condition

    checksums = parse_checksums(fixture)
    formula = render_formula(
        "v1.2.3-rc.1", checksums, "https://example.invalid/releases/v1.2.3-rc.1"
    )
    check("all four platform mappings render", all(name in formula for name in UNIX_ASSET_NAMES))
    check(
        "formula identity and test are exact",
        'version "1.2.3-rc.1"' in formula
        and 'releases/v1.2.3-rc.1/kmx-darwin-arm64' in formula
        and 'license "MIT"' in formula
        and 'shell_output("#{bin}/kmx version")' in formula,
    )
    check("formula smoke test uses the root create route",
          'shell_output("#{bin}/kmx create --help")' in formula
          and 'shell_output("#{bin}/kmx agent --help")' not in formula)
    check(
        "input order does not alter output",
        formula
        == render_formula(
            "v1.2.3-rc.1",
            parse_checksums("\n".join(reversed(fixture.splitlines()))),
            "https://example.invalid/releases/v1.2.3-rc.1",
        ),
    )

    bad_cases = {
        "a missing asset is refused": "\n".join(fixture.splitlines()[:-1]),
        "a duplicate asset is refused": fixture + "\n" + fixture.splitlines()[0],
        "a malformed digest is refused": fixture.replace("000000", "xxxxxx", 1),
        "an unexpected asset is refused": fixture + "\n" + "f" * 64 + "  notes.txt",
    }
    for name, body in bad_cases.items():
        try:
            parse_checksums(body)
        except ValueError:
            check(name, True)
        else:
            check(name, False)

    # Releases built with native Windows assets name six binaries; the four
    # Unix-only manifests already published must keep validating unchanged.
    windows_lines = [
        f"{index:064x}  {name}"
        for index, name in enumerate(sorted(WINDOWS_ASSET_NAMES), 101)
    ]
    six = "\n".join(fixture.splitlines() + windows_lines)
    check("a legacy four-asset manifest is accepted",
          sorted(parse_checksums(fixture)) == sorted(UNIX_ASSET_NAMES))
    try:
        parsed_six = parse_checksums(six)
    except ValueError:
        parsed_six = {}
    check("a six-asset manifest with both Windows binaries is accepted",
          sorted(parsed_six) == sorted(UNIX_ASSET_NAMES | WINDOWS_ASSET_NAMES))
    check("Windows assets carry the .exe GoReleaser appends to binary formats",
          WINDOWS_ASSET_NAMES == {"kmx-windows-amd64.exe", "kmx-windows-arm64.exe"})
    six_formula = render_formula(
        "v1.2.3-rc.1", unix_checksums(parsed_six),
        "https://example.invalid/releases/v1.2.3-rc.1",
    ) if parsed_six else "windows"
    check("the formula from a six-asset manifest names only the four Unix assets",
          six_formula == formula and "windows" not in six_formula)
    try:
        render_formula("v1.2.3", parsed_six, "https://example.invalid/releases")
    except ValueError:
        check("the formula renderer refuses Windows assets", bool(parsed_six))
    else:
        check("the formula renderer refuses Windows assets", False)
    try:
        required = bool(parse_checksums(six, require_windows=True))
    except ValueError:
        required = False
    check("the release build's six-asset requirement accepts a complete manifest",
          required)

    windows_bad_cases = {
        "only one Windows asset is refused": "\n".join(
            fixture.splitlines() + windows_lines[:1]),
        "the other lone Windows asset is refused": "\n".join(
            fixture.splitlines() + windows_lines[1:]),
        "Windows assets without a Unix asset are refused": "\n".join(
            fixture.splitlines()[1:] + windows_lines),
        "Windows assets alone are refused": "\n".join(windows_lines),
        "a duplicate Windows asset is refused": six + "\n" + windows_lines[0],
        "a Windows asset without .exe is refused": six.replace(
            "kmx-windows-amd64.exe", "kmx-windows-amd64"),
        "an unexpected Windows architecture is refused": six + "\n" + "e" * 64
        + "  kmx-windows-386.exe",
        "a Windows asset with a directory is refused": six.replace(
            "  kmx-windows-arm64.exe", "  dist/kmx-windows-arm64.exe"),
        "a traversing Windows asset is refused": six.replace(
            "  kmx-windows-arm64.exe", "  ..\\kmx-windows-arm64.exe"),
        "a traversing Unix asset is refused": six.replace(
            "  kmx-linux-amd64", "  ../kmx-linux-amd64"),
        "a malformed Windows digest is refused": six.replace(
            f"{101:064x}", "z" * 64),
        "a short Windows digest is refused": six.replace(
            f"{101:064x}", f"{101:063x}"),
        "an empty manifest is refused": "",
    }
    for name, body in windows_bad_cases.items():
        try:
            parse_checksums(body)
        except ValueError:
            check(name, True)
        else:
            check(name, False)
    try:
        parse_checksums(fixture, require_windows=True)
    except ValueError:
        check("the release build's six-asset requirement refuses a legacy manifest", True)
    else:
        check("the release build's six-asset requirement refuses a legacy manifest", False)

    check("hyphens inside prerelease identifiers are accepted",
          release_version("v1.2.3-x--y") == "1.2.3-x--y")
    stable_formula = render_formula(
        "v1.2.3", checksums,
        "https://github.com/kaimahi-agents/kaimahi/releases/download/v1.2.3",
    )
    check("stable release URLs use Homebrew's audited version inference",
          '  version "' not in stable_formula)
    custom_formula = render_formula(
        "v1.2.3", checksums, "https://example.invalid/releases"
    )
    check("stable custom asset bases carry an explicit version",
          'version "1.2.3"' in custom_formula)
    for bad_version in (
        "1.2.3", "v1.2", "v1.2.3/../../tap", "v01.2.3", "v1.2.3-01",
    ):
        try:
            render_formula(bad_version, checksums, "https://example.invalid/releases")
        except ValueError:
            check(f"invalid version {bad_version!r} is refused", True)
        else:
            check(f"invalid version {bad_version!r} is refused", False)

    for unsafe in ('https://example.invalid/"bad', "https://example.invalid/#{`id`}"):
        try:
            render_formula("v1.2.3", checksums, unsafe)
        except ValueError:
            check(f"unsafe asset base {unsafe!r} is refused", True)
        else:
            check(f"unsafe asset base {unsafe!r} is refused", False)

    print(f"homebrew-formula self-test: {failed} failure(s)")
    return 1 if failed else 0


def main(argv: list[str]) -> int:
    """Parse the command line and render, validate, or self-test."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version", nargs="?")
    parser.add_argument("checksums", nargs="?", type=Path)
    parser.add_argument("--asset-base")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check-version")
    parser.add_argument("--require-windows", action="store_true")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args(argv)
    if args.selftest:
        if (args.version or args.checksums or args.asset_base or args.output
                or args.check_version or args.require_windows):
            parser.error("--selftest takes no other arguments")
        return selftest()
    if args.check_version:
        if (args.version or args.checksums or args.asset_base or args.output
                or args.require_windows):
            parser.error("--check-version takes no other arguments")
        try:
            release_version(args.check_version)
        except ValueError as error:
            print(f"homebrew-formula: {error}", file=sys.stderr)
            return 1
        return 0
    if not args.version or not args.checksums:
        parser.error("version and checksums are required")
    try:
        checksums = unix_checksums(parse_checksums(
            args.checksums.read_text(), require_windows=args.require_windows))
        asset_base = args.asset_base or (
            "https://github.com/kaimahi-agents/kaimahi/releases/download/"
            + args.version
        )
        formula = render_formula(args.version, checksums, asset_base)
        if args.output:
            write_formula(args.output, formula)
        else:
            sys.stdout.write(formula)
    except (OSError, ValueError) as error:
        print(f"homebrew-formula: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
