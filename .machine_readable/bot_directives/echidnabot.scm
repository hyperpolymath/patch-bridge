;; SPDX-License-Identifier: PMPL-1.0-or-later
(bot-directive
  (bot "echidnabot")
  (scope "formal verification and fuzzing")
  (allow ("analysis" "fuzzing" "proof checks"))
  (deny ("write to core modules" "write to bindings"))
  (notes "May open findings; code changes require explicit approval")

  ;; Verification schedule and levels
  ;; Determines how and when ECHIDNA runs formal verification passes.
  ;; Levels are cumulative: each higher level includes all checks from lower levels.
  ;;
  ;; Levels:
  ;;   micro       - panic-attack + A2ML manifest validation only (fast, local, every push)
  ;;   standard    - micro + Idris2 proof compilation + ABI contract checks (weekly)
  ;;   full        - standard + Z3 refinement + session type verification (monthly, via Groove)
  ;;   attestation - full + Agda --cubical path types + signed certificate (on-demand, critical repos)
  ;;
  ;; Schedule options: "weekly" | "biweekly" | "monthly" | "on-push" | "on-demand"
  (verification
    (schedule "on-push")          ;; Template default — override per repo
    (level "micro")               ;; Template default — override per repo

    ;; Individual check toggles
    ;; Each check can be enabled (#t) or disabled (#f) independently.
    ;; Checks beyond the selected level are skipped even if enabled here
    ;; unless explicitly invoked via Groove on-demand.
    (checks
      ;; --- micro level ---
      (panic-attack #t)           ;; Surface vulnerability scan (local, fast)
      (a2ml-manifests #t)         ;; Validate A2ML manifest structure and cross-references

      ;; --- standard level ---
      (abi-contracts #t)          ;; Verify Idris2 ABI definitions compile
      (idris2-proofs #t)          ;; Check proofs compile with --total
      (ffi-contracts #t)          ;; Verify Zig FFI matches Idris2 ABI declarations
      (dependency-audit #t)       ;; cargo-audit / mix audit / etc.

      ;; --- full level ---
      (refinement-smt #t)         ;; Z3/CVC5 refinement type checking (requires Groove to full instance)
      (session-types #t)          ;; Scribble session type verification (requires Groove)

      ;; --- attestation level ---
      (cubical-paths #t))         ;; Agda --cubical path type verification (requires Groove, expensive)

    ;; Groove endpoint for remote verification (full and attestation levels)
    (groove-endpoint "groove://localhost:9700/echidna")

    ;; Output location for signed verification certificates (attestation level)
    (attestation-output ".machine_readable/attestations/")))
