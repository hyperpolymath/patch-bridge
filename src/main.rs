// SPDX-License-Identifier: PMPL-1.0-or-later
// Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>

use clap::Parser;
use patch_bridge::bridge;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the project directory
    #[arg(short, long, default_value = ".")]
    project: PathBuf,

    /// Run in offline mode (no OSV API queries)
    #[arg(short, long)]
    offline: bool,

    /// Output format (json or text)
    #[arg(short, long, default_value = "text")]
    format: String,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let report = bridge::triage(&args.project, args.offline)?;

    if args.format == "json" {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_text_report(&report);
    }

    Ok(())
}

fn print_text_report(report: &patch_bridge::bridge::BridgeReport) {
    println!("═══════════════════════════════════════════════════");
    println!("  Patch Bridge Triage Report");
    println!("═══════════════════════════════════════════════════");
    println!("Project:    {}", report.project.display());
    println!("Total deps: {}", report.total_dependencies);
    println!("Vulnerable: {}", report.vulnerable_dependencies);
    println!("───────────────────────────────────────────────────");
    println!("Mitigable:     {}", report.mitigated);
    println!("Unmitigable:   {}", report.unmitigable);
    println!("Informational: {}", report.informational);
    println!("═══════════════════════════════════════════════════");

    if !report.cves.is_empty() {
        println!("\nVulnerabilities Found:");
        for cve in &report.cves {
            println!(
                "\n[{:?}] {} — {} ({})",
                cve.classification,
                cve.vulnerability.id,
                cve.vulnerability.package,
                cve.vulnerability.version
            );
            println!("  CVSS:     {}", cve.vulnerability.severity.map_or("N/A".to_string(), |s| s.to_string()));
            println!("  Status:   {:?}", cve.reachability.status);
            println!("  Rationale: {}", cve.rationale);
            println!("  Action:    {}", cve.action);
        }
    } else {
        println!("\nNo known vulnerabilities detected.");
    }
}
