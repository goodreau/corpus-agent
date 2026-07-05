---
name: self-study
description: "Study recent topics and write focused learning summaries."
version: 1.0.0
author: Corpus Agent
license: MIT
metadata:
  hermes:
    tags: [essencia, study, learning, routine]
    related_skills: [knowledge-curator, self-analysis]
    config:
      study_topics:
        type: string
        required: false
        description: "Optional comma-separated focus topics for study runs."
---

# Self Study Skill

Review recent activity, identify knowledge gaps, and build short study outputs.
Use this skill for idle-time learning routines tied to user-relevant domains.

## When to Use

- On scheduled idle windows via cron
- When a session uncovered open questions
- When memory shows repeated unresolved topics

## Prerequisites

- Cron is enabled for the profile
- Optional `skills.config.study_topics` is set for bounded focus
- Access to recent session history and memory notes

## How to Run

- Trigger from cron or invoke the **self-study** skill directly
- Read recent topics from session and memory artifacts
- Write outputs to `memories/STUDY.md`

## Quick Reference

- Input sources: session history, `memories/KNOWLEDGE.md`
- Tool usage: `terminal`, `read_file`, `write_file`
- Output target: `memories/STUDY.md`
- Cadence: typically every 12h or daily

## Procedure

1. Gather recent topics from sessions and memory artifacts.
2. Identify top knowledge gaps and prioritize by relevance.
3. Collect references and supporting material.
4. Produce concise notes and action-oriented learning summaries.
5. Write/update `memories/STUDY.md` with date-stamped entries.

## Pitfalls

- Do not study topics disconnected from user needs.
- Do not overwrite prior study entries without preserving history.
- Do not treat weak references as verified conclusions.

## Verification

- Confirm `memories/STUDY.md` includes date, topic, findings, and next steps.
- Confirm every summary references actual retrieved material.
- Confirm no external sharing or gateway delivery was performed.
