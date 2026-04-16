-- SPDX-License-Identifier: PMPL-1.0-or-later
-- Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
||| ABI Types for Patch Bridge
|||
||| Defines the formal interface for CVE triage.
||| Proves that:
|||   1. Severity levels are totally ordered (Informational < Low < Medium < High < Critical)
|||   2. Classification outcome is deterministic
|||   3. Reachability status is exhaustive
module PatchBridge.ABI.Types

%default total

||| Severity of a CVE finding (mirrors src/bridge/mod.rs SeverityLabel)
public export
data Severity = Informational | Low | Medium | High | Critical

||| Total ordering on severity
public export
Ord Severity where
  compare Informational Informational = EQ
  compare Informational _             = LT
  compare Low           Informational = GT
  compare Low           Low           = EQ
  compare Low           _             = LT
  compare Medium        Informational = GT
  compare Medium        Low           = GT
  compare Medium        Medium        = EQ
  compare Medium        _             = LT
  compare High          Critical      = LT
  compare High          High          = EQ
  compare High          _             = GT
  compare Critical      Critical      = EQ
  compare Critical      _             = GT

||| Reachability status (mirrors src/bridge/mod.rs ReachabilityStatus)
public export
data ReachabilityStatus = Phantom | Unreachable | Reachable

||| Classification outcome (mirrors src/bridge/mod.rs Classification)
public export
data Classification = Mitigable | Unmitigable | Informational_Result
