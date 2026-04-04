// SPDX-License-Identifier: PMPL-1.0-or-later
//
// tests/property_test.rs — Property-based tests for patch-bridge classifier.
//
// Verifies invariants that must hold for all inputs in a given class:
// - Classification is deterministic (same inputs → same output)
// - Severity label derivation is monotone
// - Reachability status maps to expected classification families
// - Lockfile parser handles edge cases without panicking

use patch_bridge::bridge::{
    classify::classify,
    lockfile::parse_cargo_lock,
    reachability::check_reachability,
    Classification, ImportSite, ReachabilityEvidence, ReachabilityStatus, SeverityLabel,
    SourceTier, Vulnerability,
};
use std::io::Write;
use std::path::PathBuf;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn vuln_with_severity(score: f64, has_fix: bool, semver: bool) -> Vulnerability {
    Vulnerability {
        id: "RUSTSEC-2026-TEST".to_string(),
        cve: None,
        summary: "Property test vulnerability".to_string(),
        package: "prop-test-crate".to_string(),
        version: "1.0.0".to_string(),
        severity: Some(score),
        severity_label: SeverityLabel::from_cvss(score),
        fixed_versions: if has_fix {
            vec!["1.0.1".to_string()]
        } else {
            vec![]
        },
        semver_fix_available: semver,
        source_tier: SourceTier::Tier1,
        references: vec![],
    }
}

fn phantom_evidence() -> ReachabilityEvidence {
    ReachabilityEvidence {
        is_imported: false,
        import_sites: vec![],
        status: ReachabilityStatus::Phantom,
    }
}

fn reachable_evidence() -> ReachabilityEvidence {
    ReachabilityEvidence {
        is_imported: true,
        import_sites: vec![ImportSite {
            file: PathBuf::from("src/main.rs"),
            line: 1,
            statement: "use prop_test_crate::Api;".to_string(),
        }],
        status: ReachabilityStatus::Reachable,
    }
}

fn unreachable_evidence() -> ReachabilityEvidence {
    ReachabilityEvidence {
        is_imported: true,
        import_sites: vec![],
        status: ReachabilityStatus::Unreachable,
    }
}

// ---------------------------------------------------------------------------
// Property: Classification is deterministic
// ---------------------------------------------------------------------------

#[test]
fn prop_classify_is_deterministic_phantom_no_fix() {
    let vuln = vuln_with_severity(8.0, false, false);
    let evidence = phantom_evidence();
    let (cls1, r1, a1) = classify(&vuln, &evidence);
    let (cls2, r2, a2) = classify(&vuln, &evidence);
    assert_eq!(cls1, cls2, "Classification must be deterministic");
    assert_eq!(r1, r2, "Rationale must be deterministic");
    assert_eq!(a1, a2, "Action must be deterministic");
}

#[test]
fn prop_classify_is_deterministic_reachable_with_fix() {
    let vuln = vuln_with_severity(7.5, true, true);
    let evidence = reachable_evidence();
    let (cls1, _, _) = classify(&vuln, &evidence);
    let (cls2, _, _) = classify(&vuln, &evidence);
    assert_eq!(cls1, cls2);
}

// ---------------------------------------------------------------------------
// Property: Phantom always → Informational regardless of severity
// ---------------------------------------------------------------------------

#[test]
fn prop_phantom_always_informational_for_critical_severity() {
    let vuln = vuln_with_severity(9.8, false, false); // Critical
    let (cls, _, _) = classify(&vuln, &phantom_evidence());
    assert_eq!(cls, Classification::Informational,
        "Phantom dep must be Informational even with CVSS 9.8");
}

#[test]
fn prop_phantom_always_informational_for_medium_severity() {
    let vuln = vuln_with_severity(5.0, false, false); // Medium
    let (cls, _, _) = classify(&vuln, &phantom_evidence());
    assert_eq!(cls, Classification::Informational);
}

#[test]
fn prop_phantom_always_informational_for_low_severity() {
    let vuln = vuln_with_severity(2.0, false, false); // Low
    let (cls, _, _) = classify(&vuln, &phantom_evidence());
    assert_eq!(cls, Classification::Informational);
}

// ---------------------------------------------------------------------------
// Property: Unreachable always → Informational
// ---------------------------------------------------------------------------

#[test]
fn prop_unreachable_always_informational() {
    let vuln = vuln_with_severity(9.0, false, false);
    let (cls, _, _) = classify(&vuln, &unreachable_evidence());
    assert_eq!(cls, Classification::Informational,
        "Unreachable dep must be Informational");
}

// ---------------------------------------------------------------------------
// Property: Reachable + no fix → Unmitigable
// ---------------------------------------------------------------------------

#[test]
fn prop_reachable_no_fix_is_always_unmitigable() {
    for score in [3.0, 5.5, 7.5, 9.0, 10.0] {
        let vuln = vuln_with_severity(score, false, false);
        let (cls, _, _) = classify(&vuln, &reachable_evidence());
        assert_eq!(
            cls, Classification::Unmitigable,
            "Reachable + no fix must be Unmitigable regardless of severity (score={})",
            score
        );
    }
}

// ---------------------------------------------------------------------------
// Property: Reachable + fix → Mitigable
// ---------------------------------------------------------------------------

#[test]
fn prop_reachable_with_fix_is_always_mitigable() {
    for (has_semver, label) in [(true, "semver-fix"), (false, "breaking-fix")] {
        let vuln = vuln_with_severity(8.0, true, has_semver);
        let (cls, _, _) = classify(&vuln, &reachable_evidence());
        assert_eq!(
            cls, Classification::Mitigable,
            "Reachable + fix ({}) must be Mitigable", label
        );
    }
}

// ---------------------------------------------------------------------------
// Property: SeverityLabel::from_cvss is monotone
// ---------------------------------------------------------------------------

#[test]
fn prop_severity_label_monotone_cvss_bands() {
    // Critical ≥ 9.0
    assert_eq!(SeverityLabel::from_cvss(9.0), SeverityLabel::Critical);
    assert_eq!(SeverityLabel::from_cvss(10.0), SeverityLabel::Critical);
    // High [7.0, 9.0)
    assert_eq!(SeverityLabel::from_cvss(7.0), SeverityLabel::High);
    assert_eq!(SeverityLabel::from_cvss(8.9), SeverityLabel::High);
    // Medium [4.0, 7.0)
    assert_eq!(SeverityLabel::from_cvss(4.0), SeverityLabel::Medium);
    assert_eq!(SeverityLabel::from_cvss(6.9), SeverityLabel::Medium);
    // Low < 4.0
    assert_eq!(SeverityLabel::from_cvss(0.0), SeverityLabel::Low);
    assert_eq!(SeverityLabel::from_cvss(3.9), SeverityLabel::Low);
}

// ---------------------------------------------------------------------------
// Property: lockfile parser handles edge-case inputs without panicking
// ---------------------------------------------------------------------------

fn write_tmp_lock(content: &str) -> TempDir {
    let tmp = TempDir::new().unwrap();
    std::fs::write(tmp.path().join("Cargo.lock"), content).unwrap();
    tmp
}

#[test]
fn prop_parse_cargo_lock_handles_empty_file() {
    let tmp = write_tmp_lock("");
    let deps = parse_cargo_lock(&tmp.path().join("Cargo.lock"))
        .expect("parse_cargo_lock must not fail on empty file");
    assert!(deps.is_empty(), "Empty lockfile must produce zero deps");
}

#[test]
fn prop_parse_cargo_lock_handles_header_only() {
    let tmp = write_tmp_lock("# This file is automatically @generated by Cargo.\nversion = 4\n");
    let deps = parse_cargo_lock(&tmp.path().join("Cargo.lock"))
        .expect("parse_cargo_lock must not fail on header-only file");
    assert!(deps.is_empty(), "Header-only lockfile must produce zero deps");
}

#[test]
fn prop_parse_cargo_lock_path_dep_skipped() {
    let content = "[[package]]\nname = \"local\"\nversion = \"0.1.0\"\n\
                   source = \"path+file:///home/user/projects/local\"\n";
    let tmp = write_tmp_lock(content);
    let deps = parse_cargo_lock(&tmp.path().join("Cargo.lock"))
        .expect("parse_cargo_lock must succeed");
    // path source does not contain "registry" → must be skipped
    assert!(deps.is_empty(), "Path-source deps must be skipped");
}
