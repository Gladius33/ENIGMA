# CI and security gates

The public repository treats CI as a release barrier rather than a compile-only check.

## Android

The Android workflow runs:

- debug and release unit tests;
- debug and release Android Lint;
- Android-test compilation;
- debug APK builds;
- a release build through the real signing code path using an ephemeral CI-only key;
- APK signature verification;
- Room schema snapshot consistency;
- instrumented tests on API 26 (minSdk), API 30 and API 35 (targetSdk);
- dependency graph submission from `main`.

The emulator jobs currently execute all tests under `android/app/src/androidTest`, including Room migration and Compose UI tests.

## Server

The server workflow runs:

- `cargo fmt --check`;
- Clippy with warnings denied, all targets and all features;
- all Rust tests with the lockfile enforced;
- the declared Rust MSRV (1.94.1) compile check plus current-stable forward compatibility;
- contiguous SQL migration numbering;
- SQL migration immutability on pull requests;
- PostgreSQL, Redis and MinIO integration tests;
- production Dockerfile build;
- non-root runtime-user enforcement;
- Trivy HIGH/CRITICAL image vulnerability scan;
- full Docker Compose startup, automatic SQL migrations and live `/health` + `/version` smoke tests.

## Repository and supply chain

The security workflows add:

- full-history Gitleaks scanning;
- the project's sensitive logging policy;
- ShellCheck;
- actionlint;
- mandatory immutable commit-SHA pinning for external GitHub Actions;
- GitHub dependency review on pull requests, blocking moderate-or-higher vulnerable dependency changes;
- RustSec audit of the actual compiled release binary using `cargo-auditable` + `cargo-audit`;
- rejection of unreviewed git-sourced Cargo dependencies;
- Trivy source secret/IaC scanning plus HIGH/CRITICAL container-image vulnerability scanning;
- CodeQL extended Java/Kotlin analysis;
- OpenSSF Scorecard;
- Dependabot for GitHub Actions, Cargo and Gradle.

Scheduled security runs catch newly disclosed vulnerabilities even when the repository has not changed.

GitHub Dependency Review becomes a blocking pull-request gate as soon as the repository Dependency Graph is enabled. Until then, the workflow emits an explicit warning rather than silently pretending the check ran.

Rust advisory gating audits the dependency graph embedded in the release binary, so inactive optional crates that happen to remain represented in `Cargo.lock` do not create false-positive release failures.

## What CI cannot replace

GitHub-hosted CI cannot prove real Internet NAT traversal, carrier-network behavior, two-physical-device WebRTC/P2P reliability, push delivery on OEM devices, or radio/network transitions. Those remain part of the physical REAL LAB before a production/public-beta release.
