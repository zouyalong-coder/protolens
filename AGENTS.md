# Codeseed Agent Instructions

This repository is managed by Codeseed for project-local agent skills.

## Skills

- If `docs/context/README.md` exists, read it first when starting a new thread or when project background is unclear.
- Canonical skills live under `.agent/skills/`.
- Codeseed metadata lives under `.codeseed/`.
- Discover installed skills by scanning `.agent/skills/common/*/skill.toml` and each skill's `SKILL.md` front matter.
- When a task matches a skill's `name`, `description`, `triggers`, or `default_behavior`, read that skill's `skill.toml` and full `SKILL.md` before acting.
- Do not enumerate individual skills here. Skill-specific trigger rules and default behavior belong in the skill's own `SKILL.md` front matter.
- Before changing skill files, inspect the matching `skill.toml` and `SKILL.md`.

## Verification

- Run `cargo fmt --check` after Rust edits.
- Run `cargo test` after CLI or skill-management changes.
