#!/usr/bin/env python3
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
errors: list[str] = []

def require(condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)

license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")
require(
    license_text.startswith("GNU AFFERO GENERAL PUBLIC LICENSE\nVersion 3, 19 November 2007"),
    "LICENSE must contain the canonical GNU AGPL v3 text.",
)

readme = (ROOT / "README.md").read_text(encoding="utf-8")
require("AGPL-3.0-only" in readme, "README.md must declare AGPL-3.0-only.")

third_party = ROOT / "THIRD_PARTY_LICENSES.md"
require(third_party.is_file(), "THIRD_PARTY_LICENSES.md is required.")
if third_party.is_file():
    text = third_party.read_text(encoding="utf-8")
    require("libsignal" in text, "THIRD_PARTY_LICENSES.md must retain the libsignal notice.")
    require("AGPL-3.0-only" in text, "THIRD_PARTY_LICENSES.md must state the project SPDX license.")

for manifest in (ROOT / "server" / "Cargo.toml", ROOT / "desktop" / "Cargo.toml"):
    text = manifest.read_text(encoding="utf-8")
    require(
        'license = "AGPL-3.0-only"' in text,
        f"{manifest.relative_to(ROOT)} must declare AGPL-3.0-only.",
    )

for manifest in sorted((ROOT / "desktop" / "crates").glob("*/Cargo.toml")):
    text = manifest.read_text(encoding="utf-8")
    require(
        'license.workspace = true' in text or 'license = "AGPL-3.0-only"' in text,
        f"{manifest.relative_to(ROOT)} must inherit or declare the AGPL project license.",
    )

for manifest in ROOT.rglob("Cargo.toml"):
    rel = manifest.relative_to(ROOT)
    if any(part in {"target", ".git"} for part in rel.parts):
        continue
    text = manifest.read_text(encoding="utf-8")
    if re.search(r'^license\s*=\s*"MIT"\s*$', text, flags=re.MULTILINE):
        errors.append(f"{rel}: stale first-party MIT license declaration.")

audit = (ROOT / "docs" / "desktop-1.0-audit.md").read_text(encoding="utf-8")
require("LIC-001 — libsignal / licence — RESOLVED" in audit, "LIC-001 must remain resolved by the AGPL policy.")

if errors:
    print("\n".join(f"ERROR: {item}" for item in errors), file=sys.stderr)
    raise SystemExit(1)

print("AGPL-3.0-only repository policy verified.")
