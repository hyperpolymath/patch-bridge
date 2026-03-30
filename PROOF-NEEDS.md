# PROOF-NEEDS.md — patch-bridge

## Current State

- **src/abi/**: YES — directory exists but is EMPTY
- **Dangerous patterns**: 0 in own code (6 references are in K9 contractile guards that define ceilings)
- **LOC**: ~4,500 (Rust)
- **ABI layer**: Empty — needs Idris2 definitions

## What Needs Proving

| Component | What | Why |
|-----------|------|-----|
| CVE classify correctness | Classification assigns correct severity and category | Wrong classification leads to wrong mitigation priority |
| Lockfile parsing | Parser extracts correct dependency versions from all lockfile formats | Wrong version extraction means wrong CVE matching |
| Reachability analysis | Analysis correctly determines if vulnerable code is reachable | False reachable = wasted effort; false unreachable = missed vulnerability |
| Registry lookup | CVE registry queries return correct, complete results | Incomplete results miss known vulnerabilities |
| Patch adoption gate | Gate decision (adopt/defer/reject) is sound | Wrong gate decision either blocks good patches or admits bad ones |

## Recommended Prover

**Idris2** — Populate empty `src/abi/` with types for CVE classification, reachability analysis soundness, and adoption gate decision correctness. Small enough codebase to achieve high proof coverage.

## Priority

**HIGH** — Patch Bridge is the CVE mitigation lifecycle tool. Incorrect classification or reachability analysis directly impacts security posture. The empty ABI directory signals this work was planned but never started.

## Template ABI Cleanup (2026-03-29)

Template ABI removed -- was creating false impression of formal verification.
The removed files (Types.idr, Layout.idr, Foreign.idr) contained only RSR template
scaffolding with unresolved {{PROJECT}}/{{AUTHOR}} placeholders and no domain-specific proofs.
