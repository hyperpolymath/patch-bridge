// SPDX-License-Identifier: PMPL-1.0-or-later
//
// tests/aspect_test.rs — Security aspect tests for patch-bridge.
//
// Tests that the bridge handles invalid, malformed, and adversarial inputs
// correctly: no panics, no silent data corruption, clear error returns.
// A CVE triage tool must itself be resistant to bad input.

use patch_bridge::bridge::{
    classify::classify,
    lockfile::parse_cargo_lock,
    reachability::check_reachability,
    Classification, ImportSite, ReachabilityEvidence, ReachabilityStatus, SeverityLabel,
    SourceTier, Vulnerability,
};
use std::path::PathBuf;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

fn minimal_vuln(package: &str) -> Vulnerability {
    Vulnerability {
        id: "RUSTSEC-2026-ASPECT".to_string(),
        cve: None,
        summary: "Aspect test vuln".to_string(),
        package: package.to_string(),
        version: "0.1.0".to_string(),
        severity: None,
        severity_label: SeverityLabel::Low,
        fixed_versions: vec![],
        semver_fix_available: false,
        source_tier: SourceTier::Tier3,
        references: vec![],
    }
}

fn setup_dir(src_files: &[(&str, &str)]) -> TempDir {
    let tmp = TempDir::new().unwrap();
    if !src_files.is_empty() {
        let src = tmp.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        for (name, content) in src_files {
            std::fs::write(src.join(name), content).unwrap();
        }
    }
    tmp
}

// ---------------------------------------------------------------------------
// Aspect: lockfile parser rejects missing file with error (no panic)
// ---------------------------------------------------------------------------

#[test]
fn aspect_lockfile_missing_file_returns_error_not_panic() {
    let result = parse_cargo_lock(&PathBuf::from("/nonexistent/path/Cargo.lock"));
    assert!(result.is_err(), "Missing lockfile must return Err, not panic");
}

// ---------------------------------------------------------------------------
// Aspect: lockfile parser handles malformed content gracefully
// ---------------------------------------------------------------------------

#[test]
fn aspect_lockfile_malformed_toml_returns_empty_not_panic() {
    let tmp = TempDir::new().unwrap();
    std::fs::write(
        tmp.path().join("Cargo.lock"),
        "This is not valid TOML or Cargo.lock format at all!!!\n@@@###\n",
    ).unwrap();
    // Should return Ok with empty deps (line-by-line parser skips unrecognised lines)
    // or return Err — either way must NOT panic
    let result = parse_cargo_lock(&tmp.path().join("Cargo.lock"));
    assert!(result.is_ok(), "Malformed lockfile must not panic — got: {:?}", result);
}

#[test]
fn aspect_lockfile_dep_with_empty_name_skipped_gracefully() {
    let tmp = TempDir::new().unwrap();
    std::fs::write(
        tmp.path().join("Cargo.lock"),
        "[[package]]\nname = \"\"\nversion = \"1.0.0\"\n\
         source = \"registry+https://github.com/rust-lang/crates.io-index\"\n",
    ).unwrap();
    let result = parse_cargo_lock(&tmp.path().join("Cargo.lock"));
    assert!(result.is_ok(), "Empty dep name must not cause panic");
}

// ---------------------------------------------------------------------------
// Aspect: reachability handles empty source tree without panic
// ---------------------------------------------------------------------------

#[test]
fn aspect_reachability_empty_project_dir_is_phantom() {
    let tmp = TempDir::new().unwrap();
    // No src/ directory, no .rs files — everything is phantom
    let evidence = check_reachability(tmp.path(), "some-crate")
        .expect("check_reachability must not panic on empty dir");
    assert_eq!(evidence.status, ReachabilityStatus::Phantom,
        "No .rs files means dep is phantom");
}

#[test]
fn aspect_reachability_empty_crate_name_does_not_panic() {
    let tmp = TempDir::new().unwrap();
    let result = check_reachability(tmp.path(), "");
    assert!(result.is_ok(), "Empty crate name must not panic");
}

#[test]
fn aspect_reachability_skips_commented_out_imports() {
    let tmp = setup_dir(&[(
        "main.rs",
        "// use risky_crate::Api;\n/* use risky_crate::Other; */\nfn main() {}\n",
    )]);
    let evidence = check_reachability(tmp.path(), "risky-crate")
        .expect("reachability must succeed");
    assert!(!evidence.is_imported, "Commented-out imports must NOT count as reachable");
    assert_eq!(evidence.status, ReachabilityStatus::Phantom);
}

// ---------------------------------------------------------------------------
// Aspect: classify does not panic on adversarial / edge-case vulnerability data
// ---------------------------------------------------------------------------

#[test]
fn aspect_classify_vuln_with_no_severity_does_not_panic() {
    let vuln = minimal_vuln("no-severity-crate");
    let evidence = ReachabilityEvidence {
        is_imported: true,
        import_sites: vec![ImportSite {
            file: PathBuf::from("src/lib.rs"),
            line: 1,
            statement: "use no_severity_crate::Foo;".to_string(),
        }],
        status: ReachabilityStatus::Reachable,
    };
    // Must not panic even with None severity
    let (cls, _, _) = classify(&vuln, &evidence);
    assert_eq!(cls, Classification::Unmitigable,
        "Reachable + no fix = Unmitigable regardless of missing severity");
}

#[test]
fn aspect_classify_many_import_sites_summary_truncates() {
    // More than 3 import sites — rationale must truncate to avoid huge output
    let mut vuln = minimal_vuln("widely-used");
    vuln.fixed_versions = vec![];
    vuln.semver_fix_available = false;

    let sites: Vec<ImportSite> = (1..=5)
        .map(|i| ImportSite {
            file: PathBuf::from(format!("src/module{}.rs", i)),
            line: i,
            statement: format!("use widely_used::Mod{};", i),
        })
        .collect();

    let evidence = ReachabilityEvidence {
        is_imported: true,
        import_sites: sites,
        status: ReachabilityStatus::Reachable,
    };
    let (_cls, rationale, _action) = classify(&vuln, &evidence);
    // Should mention "more" for truncated sites
    assert!(rationale.contains("more"), "Long import list rationale must mention 'more'");
}
