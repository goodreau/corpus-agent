---
name: knowledge-curator
description: "Organize conversation knowledge into durable memory notes."
version: 1.0.0
author: Corpus Agent
license: MIT
metadata:
  hermes:
    tags: [essencia, memory, curation, knowledge]
    related_skills: [self-study, self-analysis]
---

# Knowledge Curator Skill

Capture new information from recent sessions and store it in stable memory artifacts.
Use this skill to preserve knowledge that should be reused later.

## When to Use

- After conversations that introduced new factual or procedural knowledge
- After research sessions that produced reusable conclusions
- Before closing a long task where memory continuity matters

## Prerequisites

- The `memory` feature is enabled for the profile
- Write access to the profile memory directory
- A recent conversation transcript to summarize

## How to Run

- Ask the agent to run **knowledge-curator** after a substantive turn
- Point it at the specific session or topic scope to extract
- Confirm the target file is `memories/KNOWLEDGE.md`

## Quick Reference

- Input source: recent session turns and notes
- Processing steps: extract → normalize → deduplicate → summarize
- Output target: `memories/KNOWLEDGE.md`
- Safety rule: preserve factual fidelity and avoid invention

## Procedure

1. Read recent session context and identify durable facts.
2. Normalize statements into concise, reusable knowledge entries.
3. Deduplicate against existing entries in `memories/KNOWLEDGE.md`.
4. Append only net-new, high-value knowledge.
5. End with a compact summary of what was added.

## Pitfalls

- Do not store speculative claims as facts.
- Do not copy ephemeral chatter into durable memory.
- Do not rewrite unrelated historical entries.

## Verification

- Confirm only relevant additions were written to `memories/KNOWLEDGE.md`.
- Confirm every added line maps to actual conversation evidence.
- Confirm no unrelated files were changed.
