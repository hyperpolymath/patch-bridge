# SPDX-License-Identifier: PMPL-1.0-or-later
# Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
#
# patch-bridge Justfile
# https://just.systems/man/en/

set shell := ["bash", "-uc"]
set dotenv-load := true
set positional-arguments := true

# Import auto-generated contractile recipes (must-check, trust-verify, etc.)
import? "contractile.just"

# Project metadata
project := "patch-bridge"
OWNER := "hyperpolymath"
REPO := "patch-bridge"
version := "0.1.0"
tier := "infrastructure"

# ═══════════════════════════════════════════════════════════════════════════════
# DEFAULT & HELP
# ═══════════════════════════════════════════════════════════════════════════════

# Show all available recipes
default:
    @just --list --unsorted

# Show project info
info:
    @echo "Project: {{project}}"
    @echo "Version: {{version}}"
    @echo "RSR Tier: {{tier}}"
    @[ -f ".machine_readable/STATE.a2ml" ] && grep -oP 'phase\s*=\s*"\K[^"]+' .machine_readable/STATE.a2ml | head -1 | xargs -I{} echo "Phase: {}" || true

# ═══════════════════════════════════════════════════════════════════════════════
# BUILD & COMPILE
# ═══════════════════════════════════════════════════════════════════════════════

# Build the project
build *args:
    cargo build {{args}}

# Build in release mode
build-release *args:
    cargo build --release {{args}}

# Clean build artifacts
clean:
    cargo clean

# ═══════════════════════════════════════════════════════════════════════════════
# TEST & QUALITY
# ═══════════════════════════════════════════════════════════════════════════════

# Run all tests
test *args:
    cargo test {{args}}

# Run specific test suites
test-e2e:
    cargo test --test e2e_test

test-prop:
    cargo test --test property_test

test-aspect:
    cargo test --test aspect_test

# Run all quality checks
quality: fmt-check lint test
    @echo "All quality checks passed!"

# ═══════════════════════════════════════════════════════════════════════════════
# LINT & FORMAT
# ═══════════════════════════════════════════════════════════════════════════════

# Format source files
fmt:
    cargo fmt

# Check formatting
fmt-check:
    cargo fmt --check

# Run clippy
lint:
    cargo clippy -- -D warnings

# ═══════════════════════════════════════════════════════════════════════════════
# RUN & EXECUTE
# ═══════════════════════════════════════════════════════════════════════════════

# Run the application
run *args:
    cargo run -- {{args}}

# Run triage on this project (self-test)
triage:
    cargo run -- --project . --offline

# ═══════════════════════════════════════════════════════════════════════════════
# SECURITY & COMPLIANCE
# ═══════════════════════════════════════════════════════════════════════════════

# Run security audit
security:
    cargo audit

# Run panic-attacker scan
assail:
    @command -v panic-attack >/dev/null 2>&1 && panic-attack assail . || echo "WARN: panic-attack not found"

# Validate RSR compliance
validate:
    @just validate-rsr

validate-rsr:
    #!/usr/bin/env bash
    MISSING=""
    for f in .editorconfig .gitignore Justfile README.adoc LICENSE 0-AI-MANIFEST.a2ml; do
        [ -f "$f" ] || MISSING="$MISSING $f"
    done
    if [ -n "$MISSING" ]; then
        echo "MISSING:$MISSING"
        exit 1
    fi
    echo "RSR compliance: PASS"

# ═══════════════════════════════════════════════════════════════════════════════
# UTILITIES
# ═══════════════════════════════════════════════════════════════════════════════

# Print the current CRG grade
crg-grade:
    @grade=$$(grep -oP '(?<=\*\*Current Grade:\*\* )[A-FX]' READINESS.md 2>/dev/null | head -1); \
    [ -z "$$grade" ] && grade=$$(grep -oP '(?<=\*\*Current Grade:\*\* )[A-FX]' TEST-NEEDS.md 2>/dev/null | head -1); \
    [ -z "$$grade" ] && grade="X"; \
    echo "$$grade"

# Count lines of code
loc:
    @find . \( -name "*.rs" -o -name "*.idr" -o -name "*.zig" \) -not -path './target/*' 2>/dev/null | xargs wc -l | tail -1

# Show recent commits
log count="20":
    @git log --oneline -{{count}}
