// SPDX-License-Identifier: PMPL-1.0-or-later
//
// benches/bridge_bench.rs — Criterion benchmarks for patch-bridge.
//
// Measures the throughput of the lockfile parser, reachability checker,
// and classifier to identify performance regressions in the triage pipeline.
//
// Run with: cargo bench

use criterion::{black_box, criterion_group, criterion_main, Criterion};
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
// Fixture builders
// ---------------------------------------------------------------------------

/// Build a Cargo.lock string with `n` synthetic registry dependencies.
fn build_cargo_lock(n: usize) -> String {
    let mut out = "# Auto-generated Cargo.lock.\nversion = 4\n\n".to_string();
    for i in 0..n {
        out.push_str(&format!(
            "[[package]]\nname = \"dep-{}\"\nversion = \"1.0.{}\"\n\
             source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
             checksum = \"deadbeef{:04x}\"\n\n",
            i, i, i
        ));
    }
    out
}

/// Write a lockfile into a temp dir and return (TempDir, PathBuf to Cargo.lock).
fn write_lockfile(content: &str) -> (TempDir, PathBuf) {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("Cargo.lock");
    std::fs::write(&path, content).unwrap();
    (tmp, path)
}

/// Build a synthetic Vulnerability for benchmarking.
fn bench_vuln(has_fix: bool, semver: bool) -> Vulnerability {
    Vulnerability {
        id: "RUSTSEC-BENCH-0001".to_string(),
        cve: Some("CVE-BENCH-0001".to_string()),
        summary: "Benchmark advisory — synthetic data".to_string(),
        package: "bench-crate".to_string(),
        version: "1.2.3".to_string(),
        severity: Some(8.5),
        severity_label: SeverityLabel::High,
        fixed_versions: if has_fix {
            vec!["1.3.0".to_string()]
        } else {
            vec![]
        },
        semver_fix_available: semver,
        source_tier: SourceTier::Tier1,
        references: vec!["https://rustsec.org/advisories/RUSTSEC-BENCH-0001.html".to_string()],
    }
}

fn bench_reachable_evidence() -> ReachabilityEvidence {
    ReachabilityEvidence {
        is_imported: true,
        import_sites: vec![
            ImportSite {
                file: PathBuf::from("src/main.rs"),
                line: 1,
                statement: "use bench_crate::Client;".to_string(),
            },
            ImportSite {
                file: PathBuf::from("src/handler.rs"),
                line: 42,
                statement: "use bench_crate::Request;".to_string(),
            },
        ],
        status: ReachabilityStatus::Reachable,
    }
}

fn bench_phantom_evidence() -> ReachabilityEvidence {
    ReachabilityEvidence {
        is_imported: false,
        import_sites: vec![],
        status: ReachabilityStatus::Phantom,
    }
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

/// Benchmark lockfile parsing for small (5), medium (25), and large (100) inputs.
fn bench_lockfile_parsing(c: &mut Criterion) {
    let small_lock  = build_cargo_lock(5);
    let medium_lock = build_cargo_lock(25);
    let large_lock  = build_cargo_lock(100);

    let (_t1, small_path)  = write_lockfile(&small_lock);
    let (_t2, medium_path) = write_lockfile(&medium_lock);
    let (_t3, large_path)  = write_lockfile(&large_lock);

    let mut group = c.benchmark_group("lockfile_parsing");

    group.bench_function("parse 5 deps",   |b| b.iter(|| parse_cargo_lock(black_box(&small_path)).unwrap()));
    group.bench_function("parse 25 deps",  |b| b.iter(|| parse_cargo_lock(black_box(&medium_path)).unwrap()));
    group.bench_function("parse 100 deps", |b| b.iter(|| parse_cargo_lock(black_box(&large_path)).unwrap()));

    group.finish();
}

/// Benchmark the classify function for the three main outcome paths.
fn bench_classify(c: &mut Criterion) {
    let vuln_no_fix    = bench_vuln(false, false);
    let vuln_semver    = bench_vuln(true, true);
    let vuln_breaking  = bench_vuln(true, false);
    let reachable_ev   = bench_reachable_evidence();
    let phantom_ev     = bench_phantom_evidence();

    let mut group = c.benchmark_group("classify");

    group.bench_function("phantom → informational", |b| {
        b.iter(|| classify(black_box(&vuln_no_fix), black_box(&phantom_ev)))
    });
    group.bench_function("reachable no fix → unmitigable", |b| {
        b.iter(|| classify(black_box(&vuln_no_fix), black_box(&reachable_ev)))
    });
    group.bench_function("reachable semver fix → mitigable", |b| {
        b.iter(|| classify(black_box(&vuln_semver), black_box(&reachable_ev)))
    });
    group.bench_function("reachable breaking fix → mitigable", |b| {
        b.iter(|| classify(black_box(&vuln_breaking), black_box(&reachable_ev)))
    });

    group.finish();
}

/// Benchmark reachability scanning for a small project directory.
fn bench_reachability(c: &mut Criterion) {
    // Build a temp project with a handful of .rs files
    let tmp = TempDir::new().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir_all(&src).unwrap();

    for i in 0..10 {
        let content = format!(
            "use bench_crate::Module{};\nuse other_crate::Util;\nfn func_{}() {{}}\n",
            i, i
        );
        std::fs::write(src.join(format!("module{}.rs", i)), content).unwrap();
    }

    let mut group = c.benchmark_group("reachability");

    group.bench_function("scan 10 src files (reachable)", |b| {
        b.iter(|| check_reachability(black_box(tmp.path()), black_box("bench-crate")).unwrap())
    });
    group.bench_function("scan 10 src files (phantom)", |b| {
        b.iter(|| check_reachability(black_box(tmp.path()), black_box("not-present-crate")).unwrap())
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Criterion entry point
// ---------------------------------------------------------------------------

criterion_group!(
    benches,
    bench_lockfile_parsing,
    bench_classify,
    bench_reachability
);
criterion_main!(benches);
