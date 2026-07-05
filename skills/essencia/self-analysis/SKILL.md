---
name: self-analysis
description: "Analyze sessions and usage patterns for improvements."
version: 1.0.0
author: Corpus Agent
license: MIT
metadata:
  hermes:
    tags: [essencia, analysis, improvement, reflection]
    related_skills: [knowledge-curator, self-study]
---

# Self Analysis Skill

Inspect session history and skill usage to generate concrete improvement actions.
Use this skill for periodic quality review and operating refinement.

## When to Use

- Weekly review cycles
- After repeated execution failures or regressions
- Before adjusting routines, prompts, or skill organization

## Prerequisites

- Access to recent session history
- Access to skill usage data (`.usage.json`)
- Write access to `memories/ANALYSIS.md`

## How to Run

- Invoke **self-analysis** on a weekly schedule
- Read usage and session artifacts
- Write recommendations into `memories/ANALYSIS.md`

## Quick Reference

- Inputs: session summaries, `.usage.json`, memory notes
- Tools: `read_file`, session search tooling
- Output: `memories/ANALYSIS.md`
- Goal: actionable improvements, not generic commentary

## Procedure

1. Review usage frequency and recent session outcomes.
2. Identify recurring bottlenecks and quality issues.
3. Propose specific, testable improvements.
4. Rank recommendations by impact and implementation effort.
5. Record findings in `memories/ANALYSIS.md`.

## Pitfalls

- Do not produce abstract feedback without clear actions.
- Do not ignore high-frequency failure patterns.
- Do not remove historical analysis context.

## Verification

- Confirm each recommendation maps to observed evidence.
- Confirm analysis entries are prioritized and concise.
- Confirm output is saved to `memories/ANALYSIS.md` only.
