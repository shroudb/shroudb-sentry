# Changelog

All notable changes to ShrouDB Sentry are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [v1.4.11] - 2026-04-09

### Added

- adapt to chronicle-core 1.3.0 event model
- policy versioning and configurable audit mode (LOW-13, LOW-14)

### Fixed

- adapt Event::new to chronicle-core 1.5.0 resource_type field

## [v1.4.10] - 2026-04-04

### Changed

- use shared ServerAuthConfig from shroudb-acl

## [v1.4.9] - 2026-04-02

### Fixed

- use entrypoint script to fix volume mount permissions

### Other

- Use check_dispatch_acl for consistent ACL error formatting

## [v1.4.8] - 2026-04-01

### Other

- Migrate Sentry client to shroudb-client-common

## [v1.4.7] - 2026-04-01

### Other

- Migrate TCP handler to shroudb-server-tcp

## [v1.4.6] - 2026-04-01

### Other

- Wire shroudb-server-bootstrap, eliminate startup boilerplate
- Add storage corruption recovery test

## [v1.4.5] - 2026-04-01

### Other

- Arc-wrap SigningKeyring cache, eliminate key material cloning

## [v1.4.4] - 2026-04-01

### Other

- Implement Sentry self-authorization for policy mutations

## [v1.4.3] - 2026-04-01

### Other

- Fail-closed audit for security-critical operations
- Redact private_key in SigningKeyVersion Debug output

## [v1.4.2] - 2026-03-31

### Other

- Add unit tests to sentry-core: decision types, policy matching (v1.4.2)

## [v1.4.1] - 2026-03-31

### Other

- Add edge case tests: max-length policy name, name too long (v1.4.1)

## [v1.4.0] - 2026-03-31

### Other

- Wire ChronicleOps audit events into Sentry engine (v1.4.0)

## [v1.3.2] - 2026-03-31

### Other

- Remove dead config() accessor, add concurrent test (v1.3.2)

## [v1.3.1] - 2026-03-31

### Other

- Harden server: expect context on unwraps, add concurrency test (v1.3.1)
- Wire actor identity + scheduler graceful shutdown
- Implement PolicyEvaluator trait on SentryEngine (v1.2.0)
- Harden Sentry v1.1.0: dedup boilerplate

## [v1.0.0] - 2026-03-30

### Other

- ShrouDB Sentry v1.0.0 — policy-based authorization engine

