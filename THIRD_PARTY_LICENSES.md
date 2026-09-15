# Third-party licenses

ENIGMA itself is licensed under **AGPL-3.0-only**. See [LICENSE](LICENSE).

Third-party software included, linked, downloaded, or used to build ENIGMA remains governed by its own copyright and license terms. ENIGMA does not relicense third-party code.

## libsignal

ENIGMA uses Signal's libsignal implementation for Signal Protocol functionality. The Android dependency is pinned by the project dependency catalog, and the desktop backend uses an exact reviewed source revision for RC 1.0.

libsignal is an upstream Signal project and retains its upstream copyright and licensing notices. Its source distribution identifies **AGPL-3.0-only**.

Upstream project: https://github.com/signalapp/libsignal

## libsodium / Rust bindings

The desktop secure-memory and local-record encryption boundary uses `libsodium-sys-stable 1.24.0`, which is distributed under `MIT OR Apache-2.0`, and builds/links libsodium. libsodium and its bindings retain their upstream copyright and license notices.

Upstream bindings: https://github.com/jedisct1/libsodium-sys-stable

## Windows DPAPI wrapper

The Windows desktop key-protection boundary uses `windows-dpapi 0.2.0`, distributed under `MIT OR Apache-2.0`, to access the Windows Data Protection API through a safe Rust wrapper. ENIGMA uses current-user scope for per-user storage-master-key protection.

Upstream project: https://github.com/sheridans/windows-dpapi

## Linux Secret Service binding

The Linux desktop key-protection boundary uses `secret-service 5.2.0`, distributed under `MIT OR Apache-2.0`, to access a freedesktop Secret Service provider such as GNOME Keyring or KWallet. ENIGMA requests an encrypted DH Secret Service session and stores only an opaque locator outside the provider.

Upstream project: https://github.com/hwchen/secret-service-rs

## Other dependencies

Rust, Android, .NET/Windows, Qt/Linux and build-time dependencies retain their respective upstream licenses. Lockfiles and dependency manifests define the exact dependency graph used by a build.

Release packaging must preserve all notices required by bundled dependencies. Dependency-review and release SBOM gates are part of the ENIGMA 1.0 release process.

## Project copyright

Copyright (C) 2025-2026 Sébastien TOUILLEUX (Gladius33).

SPDX project license identifier: `AGPL-3.0-only`.
