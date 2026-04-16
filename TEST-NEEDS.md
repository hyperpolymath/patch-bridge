# TEST-NEEDS.md — patch-bridge

## CRG Grade: C — ACHIEVED 2026-04-04

> Generated 2026-03-29 by punishing audit.

## Current State

| Category     | Count | Notes |
|-------------|-------|-------|
| Unit tests   | 14    | bridge: classify(4), intelligence(2), lockfile(2), reachability(4), registry(2) |
| Integration  | 1     | src/interface/ffi/test/build.zig |
| E2E          | 11    | tests/e2e_test.rs |
| Property     | 12    | tests/property_test.rs |
| Aspect       | 8     | tests/aspect_test.rs |
| Benchmarks   | 1     | benches/bridge_bench.rs |

**Source modules:** ~11 Rust source files in src/bridge/ + 3 Idris2 ABI + 1 Zig FFI.

## What's Missing

### P2P (Property-Based) Tests
- [ ] CVE classification: property tests for severity scoring consistency
- [ ] Lockfile parsing: arbitrary lockfile format fuzzing (Cargo.lock, package-lock.json, mix.lock, etc.)
- [ ] Reachability: property tests for call graph analysis correctness
- [ ] Registry: property tests for advisory lookup consistency

### E2E Tests
- [ ] Full CVE lifecycle: detect -> classify -> assess reachability -> recommend mitigation -> verify fix
- [ ] Multi-format: lockfile parsing across all supported package managers
- [ ] Intelligence: advisory fetch -> parse -> match to dependencies
- [ ] Adoption gate: recommend patch -> apply -> verify -> close

### Aspect Tests
- **Security:** A CVE mitigation tool needs security testing: false negative detection (missed CVEs), advisory tampering, lockfile injection — ZERO security tests
- **Performance:** No benchmarks for lockfile parsing speed, CVE database lookup time, reachability analysis scaling
- **Concurrency:** No tests for parallel vulnerability assessment, concurrent advisory fetches
- **Error handling:** No tests for malformed lockfiles, unreachable registries, invalid CVE identifiers, network timeouts

### Build & Execution
- [ ] `cargo test`
- [ ] Zig FFI test execution
- [ ] CLI smoke tests with real lockfiles

### Benchmarks Needed
- [ ] Lockfile parsing time per format
- [ ] Reachability analysis time vs dependency graph size
- [ ] Advisory lookup latency
- [ ] Full assessment pipeline throughput

### Self-Tests
- [ ] Assess its own Cargo.lock for vulnerabilities
- [ ] Registry connectivity health check
- [ ] Classification model consistency verification

## Priority

**CRITICAL.** A CVE mitigation lifecycle tool with 14 inline unit tests and ZERO E2E tests. The reachability and classification modules have the most tests (good). But no integration testing means the pieces are never validated together. A security tool that cannot test its own security posture is self-refuting. No benchmarks for what should be a performance-sensitive pipeline.

## FAKE-FUZZ ALERT

- `tests/fuzz/placeholder.txt` is a scorecard placeholder inherited from rsr-template-repo — it does NOT provide real fuzz testing
- Replace with an actual fuzz harness (see rsr-template-repo/tests/fuzz/README.adoc) or remove the file
- Priority: P2 — creates false impression of fuzz coverage
