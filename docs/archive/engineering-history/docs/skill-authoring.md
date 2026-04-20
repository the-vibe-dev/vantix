# Skill Authoring

Skill packs live under `agent_skills/` and are loaded from `agent_skills/registry.yaml`.

## Structure

```text
agent_skills/
  registry.yaml
  shared/
    evidence_rules.md
    execution_policy.md
    memory_protocol.md
    scope_guard.md
  packs/<skill_id>/
    metadata.yaml
    SKILL.md
```

## Metadata

Required fields:

```yaml
id: web_hunter
name: Web Hunter
version: 1
summary: concise purpose
roles: [recon, researcher]
modes: [pentest, ctf, bugbounty]
execution_level: advisory
safety_level: active
tags: [web]
requires_scope: true
forbidden: [destructive, dos, out_of_scope]
```

`execution_level` values:

- `advisory`: analysis, planning, reporting, or tool guidance only.
- `gated`: may suggest active validation, but requires explicit scope/approval gates.
- `active`: may be used by executor only when run controls allow execution.

## SKILL.md Style

Keep skills short and operational. Prefer compact checklists and output schemas. Avoid teaching prose and long background explanations.

Good style:

```text
Emit: svc[], vulns[], evidence[], next[]. Block if scope unknown.
```

Bad style:

```text
SQL injection is a web vulnerability that occurs when...
```

## Selection

Skill selection is implemented in `secops/services/skills.py`:

- `ROLE_DEFAULTS`: baseline packs per specialist.
- `MODE_DEFAULTS`: packs added for `ctf`, `bugbounty`, Windows, or KoTH modes.
- `KEYWORD_SKILLS`: packs added from target/objective/fact keywords.

When adding a new skill, update the registry and add tests if it changes selection or safety behavior.
