# Security Policy

ENIGMA handles end-to-end encrypted messaging, device identities and encrypted local state. Do not disclose exploitable vulnerabilities in public issues, pull requests or discussions before coordinated remediation.

## Supported target

The intended supported target for the 1.0 line is the latest signed 1.0 release candidate/release and the current `main` branch only after all required security gates pass. Development branches may be incomplete and are not production security guarantees.

## Reporting

Use GitHub private vulnerability reporting when it is enabled for this repository. Otherwise use an already established trusted private maintainer channel before transmitting sensitive exploit details.

Never include real account secrets, private keys, recovery material, production tokens, personal message content or production database dumps in a report.

## Priority classes

High-priority reports include plaintext exposure, authentication/device-link bypass, server-side device injection, identity-key substitution, replay/deduplication failure, downgrade acceptance, relay TTL/delete failure, attachment-key leakage, local-vault compromise, secret logging and memory/FFI safety defects.

Security fixes should include regression tests whenever practical.
