# SPDX-License-Identifier: PMPL-1.0-or-later
# Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
#
# K9 Validator: Patch Bridge Methodology Guard
# Ensures that CVE classification, lockfile parsing, reachability analysis, and registry lookups align
# with the methodology ergonomics declared in agent_instructions/methodology.a2ml.

let methodology_guard = {
  name = "patch-bridge-methodology-guard",
  version = "1.0.0",
  description = "Validates that the bridge modules remain present, coverage metadata is fresh, and template placeholders are removed.",

  checks = {
    divergent_invariant_language = {
      description = "No files introduce a disallowed language variant in the proof directories.",
      severity = "error",
      check_type = "file-extension-guard",
      scope = "src/",
    },

    believe_me_ceiling = {
      description = "believe_me occurrences do not exceed the declared ceiling (0 by default).",
      severity = "error",
      pattern = "believe_me",
      ceiling_key = "methodology.divergent-invariants.believe-me-ceiling",
      default_ceiling = 0,
    },

    assert_total_ceiling = {
      description = "assert_total usage stays within the declared ceiling (0 by default).",
      severity = "error",
      pattern = "assert_total",
      ceiling_key = "methodology.divergent-invariants.assert-total-ceiling",
      default_ceiling = 0,
    },

    state_not_template = {
      description = "STATE.a2ml must not contain template placeholders.",
      severity = "warning",
      file = ".machine_readable/6a2/STATE.a2ml",
      reject_patterns = ["", "PATCH_BRIDGE", "rsr-template-repo"],
    },

    coverage_updated = {
      description = "coverage.a2ml should be refreshed within the last 30 days.",
      severity = "info",
      file = ".machine_readable/agent_instructions/coverage.a2ml",
      staleness_days = 30,
    },

    classify_module = {
      description = "CVE classification belongs to src/bridge/classify.rs.",
      severity = "error",
      check_type = "file-exists",
      file = "src/bridge/classify.rs",
    },

    lockfile_module = {
      description = "Lockfile parsing logic is still present.",
      severity = "error",
      check_type = "file-exists",
      file = "src/bridge/lockfile.rs",
    },

    reachability_module = {
      description = "Reachability analysis module remains versioned.",
      severity = "warning",
      check_type = "file-exists",
      file = "src/bridge/reachability.rs",
    },

    registry_module = {
      description = "Registry lookup helper is tracked.",
      severity = "warning",
      check_type = "file-exists",
      file = "src/bridge/registry.rs",
    },

    interface_test = {
      description = "The Zig FFI integration test supports the adoption gate.",
      severity = "warning",
      check_type = "file-exists",
      file = "src/interface/ffi/test/integration_test.zig",
    },

    no_template_files = {
      description = "Remove any rsr-template placeholders.",
      severity = "error",
      check_type = "file-pattern-guard",
      scope = ".",
      reject_patterns = ["PATCH_BRIDGE", "hyperpolymath", "Jonathan D.A. Jewell"],
    },

    no_placeholder_fuzz = {
      description = "Placeholder fuzz harnesses should not exist.",
      severity = "warning",
      check_type = "file-not-exists",
      file = "tests/fuzz/placeholder.txt",
    },
  },
}
in methodology_guard
