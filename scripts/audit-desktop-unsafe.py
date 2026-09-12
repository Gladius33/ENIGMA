#!/usr/bin/env python3
from pathlib import Path
import re
import sys

ROOT = Path("desktop/crates")
ALLOWED = {"enigma-ffi", "enigma-platform"}
failures: list[str] = []

for path in sorted(ROOT.glob("*/src/**/*.rs")):
    crate = path.relative_to(ROOT).parts[0]
    lines = path.read_text(encoding="utf-8").splitlines()
    for index, line in enumerate(lines):
        if re.search(r"\bunsafe\s*\{", line):
            if crate not in ALLOWED:
                failures.append(f"{path}:{index + 1}: unsafe block outside allowed boundary")
                continue
            context = "\n".join(lines[max(0, index - 5): index])
            if "// SAFETY:" not in context:
                failures.append(f"{path}:{index + 1}: unsafe block missing nearby // SAFETY: comment")
        elif crate not in ALLOWED:
            code = line.strip()
            if "forbid(unsafe_code)" in code or "deny(unsafe_op_in_unsafe_fn)" in code:
                continue
            if re.search(r"\bunsafe\s+(fn|impl|trait)\b", code):
                failures.append(f"{path}:{index + 1}: unsafe item outside allowed boundary")

for crate_dir in sorted(ROOT.iterdir()):
    if not crate_dir.is_dir() or crate_dir.name in ALLOWED:
        continue
    lib = crate_dir / "src/lib.rs"
    if lib.exists() and "#![forbid(unsafe_code)]" not in lib.read_text(encoding="utf-8"):
        failures.append(f"{lib}: missing #![forbid(unsafe_code)]")

if failures:
    print("\n".join(failures))
    sys.exit(1)
print("Desktop unsafe policy OK: unsafe is confined to reviewed FFI/platform boundaries.")
