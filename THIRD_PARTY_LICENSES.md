# Third-party licenses

ENIGMA itself is licensed under **AGPL-3.0-only**. See [LICENSE](LICENSE).

Third-party software included, linked, downloaded, or used to build ENIGMA remains governed by its own copyright and license terms. ENIGMA does not relicense third-party code.

## libsignal

ENIGMA uses Signal's libsignal implementation for Signal Protocol functionality. The Android dependency is pinned by the project dependency catalog, and the desktop backend must use an exact reviewed source revision before RC 1.0.

libsignal is an upstream Signal project and retains its upstream copyright and licensing notices. Its source distribution identifies **AGPL-3.0-only**.

Upstream project: https://github.com/signalapp/libsignal

## Other dependencies

Rust, Android, .NET/Windows, Qt/Linux and build-time dependencies retain their respective upstream licenses. Lockfiles and dependency manifests define the exact dependency graph used by a build.

Release packaging must preserve all notices required by bundled dependencies. Dependency-review and release SBOM gates are part of the ENIGMA 1.0 release process.

## Project copyright

Copyright (C) 2025-2026 Sébastien TOUILLEUX (Gladius33).

SPDX project license identifier: `AGPL-3.0-only`.
