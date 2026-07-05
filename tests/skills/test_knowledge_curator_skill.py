from __future__ import annotations

import re
from pathlib import Path

import yaml


SKILL_DIR = Path(__file__).resolve().parents[2] / "skills" / "essencia" / "knowledge-curator"
SKILL_MD = SKILL_DIR / "SKILL.md"


def _frontmatter() -> dict:
    src = SKILL_MD.read_text(encoding="utf-8")
    match = re.search(r"^---\n(.*?)\n---", src, re.DOTALL)
    assert match, "SKILL.md missing YAML frontmatter"
    return yaml.safe_load(match.group(1))


def test_skill_file_exists() -> None:
    assert SKILL_MD.is_file()


def test_description_under_60_chars() -> None:
    desc = _frontmatter()["description"]
    assert len(desc) <= 60


def test_platforms_not_declared() -> None:
    assert "platforms" not in _frontmatter()


def test_required_sections_present() -> None:
    body = SKILL_MD.read_text(encoding="utf-8")
    for section in (
        "## When to Use",
        "## Prerequisites",
        "## How to Run",
        "## Quick Reference",
        "## Procedure",
        "## Pitfalls",
        "## Verification",
    ):
        assert section in body
