from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
import re

import yaml
from sqlalchemy.orm import Session

from secops.config import settings
from secops.models import AgentSession, Fact, Finding, ProviderConfig, RunEvent, WorkspaceRun
from secops.services.events import RunEventService
from secops.services.storage import StorageLayout


@dataclass(frozen=True)
class SkillPack:
    id: str
    name: str
    version: int
    summary: str
    roles: list[str]
    modes: list[str]
    execution_level: str
    safety_level: str
    tags: list[str]
    requires_scope: bool
    forbidden: list[str]
    body: str
    editable: bool = False

    def public(self, reason: str = "") -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "summary": self.summary,
            "roles": self.roles,
            "modes": self.modes,
            "execution_level": self.execution_level,
            "safety_level": self.safety_level,
            "tags": self.tags,
            "requires_scope": self.requires_scope,
            "forbidden": self.forbidden,
            "reason": reason,
            "editable": self.editable,
        }


ROLE_DEFAULTS: dict[str, list[str]] = {
    "orchestrator": ["scope_guard", "swarm_orchestrator", "engagement_planner", "attack_planner", "threat_modeler"],
    "recon": ["scope_guard", "recon_advisor", "osint_collector", "web_hunter"],
    "knowledge_base": ["scope_guard", "ctf_solver", "forensics_analyst"],
    "vector_store": ["scope_guard", "attack_planner", "exploit_chainer", "poc_validator"],
    "researcher": ["scope_guard", "vuln_scanner", "api_security", "web_hunter", "cloud_security", "ad_attacker"],
    "developer": ["scope_guard", "poc_validator", "exploit_guide", "privesc_advisor"],
    "executor": ["scope_guard", "poc_validator", "exploit_chainer"],
    "reporter": ["scope_guard", "report_generator", "detection_engineer", "threat_modeler"],
}

MODE_DEFAULTS: dict[str, list[str]] = {
    "ctf": ["ctf_solver", "privesc_advisor", "forensics_analyst"],
    "koth": ["ctf_solver", "privesc_advisor", "attack_planner"],
    "bugbounty": ["bug_bounty", "web_hunter", "api_security", "bizlogic_hunter"],
    "windows-ctf": ["ctf_solver", "ad_attacker", "privesc_advisor"],
    "windows-koth": ["ctf_solver", "ad_attacker", "privesc_advisor"],
}

KEYWORD_SKILLS: list[tuple[tuple[str, ...], str]] = [
    (("http", "web", "url", "xss", "sqli", "sql injection", "ssrf"), "web_hunter"),
    (("api", "graphql", "jwt", "oauth", "swagger"), "api_security"),
    (("ad", "ldap", "kerberos", "smb", "domain", "windows"), "ad_attacker"),
    (("cloud", "s3", "iam", "metadata", "bucket"), "cloud_security"),
    (("mobile", "apk", "android", "ios"), "mobile_pentester"),
    (("wireless", "wifi", "802.11"), "wireless_pentester"),
    (("malware", "yara", "sandbox"), "malware_analyst"),
    (("forensic", "pcap", "memory dump", "timeline"), "forensics_analyst"),
    (("credential", "password", "hash", "ntlm", "kerberoast"), "credential_tester"),
    (("cicd", "pipeline", "jenkins", "github actions", "runner"), "cicd_redteam"),
]

SERVICE_TAGS = {
    "http": "web",
    "https": "web",
    "apache": "web",
    "nginx": "web",
    "wordpress": "web",
    "smb": "smb",
    "ldap": "ad",
    "kerberos": "ad",
    "winrm": "windows",
    "rdp": "windows",
    "ssh": "ssh",
    "openssh": "ssh",
    "ftp": "ftp",
    "redis": "redis",
    "mysql": "db",
    "postgres": "db",
    "mssql": "db",
}


def _csv(values: list[str]) -> str:
    return ",".join(sorted({item for item in values if item}))


def focus_from_facts(run: WorkspaceRun, facts: list[Fact], role: str = "") -> str:
    tags = list(run.config_json.get("tags", [])) + [run.mode]
    ports = list(run.config_json.get("ports", []))
    services = list(run.config_json.get("services", []))
    versions: list[str] = []
    cves: list[str] = []
    for fact in facts:
        meta = fact.metadata_json or {}
        if fact.kind in {"port"}:
            ports.append(str(fact.value))
        if fact.kind in {"service"}:
            services.append(str(fact.value).lower())
        if fact.kind in {"version", "banner"}:
            versions.append(str(fact.value))
        if fact.kind == "cve":
            cves.append(str(fact.value))
        for key in ("port", "service", "version", "cve"):
            value = meta.get(key)
            if value and key == "port":
                ports.append(str(value))
            elif value and key == "service":
                services.append(str(value).lower())
            elif value and key == "version":
                versions.append(str(value))
            elif value and key == "cve":
                cves.append(str(value))
    haystack = " ".join([run.target or "", run.objective or "", *services, *versions]).lower()
    for service, tag in SERVICE_TAGS.items():
        if service in haystack:
            tags.append(tag)
    phase = "recon" if role == "recon" else "research" if role == "researcher" else "plan" if role in {"orchestrator", "vector_store"} else "execute" if role == "executor" else role or "all"
    return (
        f"mode={run.mode} tags={_csv(tags)} ports={_csv(ports)} svc={_csv(services)} "
        f"versions={_csv(versions)} cves={_csv(cves)} phase={phase} role={role or '*'}"
    )


def load_lookup_guide(limit: int = 18) -> str:
    path = settings.repo_root / "LOOKUP.md"
    if not path.exists():
        return "lookup_guide=missing refs=LOOKUP.md"
    lines = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        stripped = line.strip()
        if stripped.startswith("id=lookup.") or stripped.startswith("focus_schema:") or stripped.startswith("rule:"):
            lines.append(stripped)
        if len(lines) >= limit:
            break
    return "\n".join(lines)


class SkillRegistry:
    def __init__(self, root: Path | None = None) -> None:
        self.root = (root or settings.skills_root).resolve()
        self.registry_path = self.root / "registry.yaml"
        self.local_root = self.root / "packs" / "local"
        self.shared_paths: list[Path] = []
        self._packs: dict[str, SkillPack] = {}
        self._load()

    def _load(self) -> None:
        if not self.registry_path.exists():
            return
        data = yaml.safe_load(self.registry_path.read_text(encoding="utf-8")) or {}
        self.shared_paths = [self.root / item for item in data.get("shared", [])]
        for item in data.get("packs", []):
            meta_path = self.root / item["metadata"]
            skill_path = self.root / item["skill"]
            pack = self._pack_from_files(meta_path, skill_path, editable=False)
            self._packs[pack.id] = pack
        if self.local_root.exists():
            for directory in sorted(path for path in self.local_root.iterdir() if path.is_dir()):
                meta_path = directory / "metadata.yaml"
                skill_path = directory / "SKILL.md"
                if not meta_path.exists() or not skill_path.exists():
                    continue
                pack = self._pack_from_files(meta_path, skill_path, editable=True)
                self._packs[pack.id] = pack

    def _pack_from_files(self, meta_path: Path, skill_path: Path, *, editable: bool) -> SkillPack:
        meta = yaml.safe_load(meta_path.read_text(encoding="utf-8")) or {}
        return SkillPack(
            id=str(meta["id"]),
            name=str(meta["name"]),
            version=int(meta.get("version", 1)),
            summary=str(meta.get("summary", "")),
            roles=list(meta.get("roles", [])),
            modes=list(meta.get("modes", [])),
            execution_level=str(meta.get("execution_level", "advisory")),
            safety_level=str(meta.get("safety_level", "active")),
            tags=list(meta.get("tags", [])),
            requires_scope=bool(meta.get("requires_scope", False)),
            forbidden=list(meta.get("forbidden", [])),
            body=skill_path.read_text(encoding="utf-8"),
            editable=editable,
        )

    def all(self) -> list[SkillPack]:
        return sorted(self._packs.values(), key=lambda item: item.id)

    def get(self, skill_id: str) -> SkillPack | None:
        return self._packs.get(skill_id)

    def shared_text(self) -> str:
        chunks = []
        for path in self.shared_paths:
            if path.exists():
                chunks.append(path.read_text(encoding="utf-8"))
        return "\n\n".join(chunks)

    def reload(self) -> list[SkillPack]:
        self._packs = {}
        self._load()
        return self.all()

    def create_local(self, payload: dict[str, Any]) -> SkillPack:
        skill_id = self._normalize_id(str(payload.get("id") or ""))
        if not skill_id:
            raise ValueError("Skill id is required")
        existing = self.get(skill_id)
        if existing is not None:
            raise ValueError("Skill id already exists")
        directory = self.local_root / skill_id
        directory.mkdir(parents=True, exist_ok=True)
        meta_path = directory / "metadata.yaml"
        skill_path = directory / "SKILL.md"
        meta = self._metadata_from_payload(skill_id, payload, version=int(payload.get("version") or 1))
        meta_path.write_text(yaml.safe_dump(meta, sort_keys=False), encoding="utf-8")
        skill_path.write_text(str(payload.get("body") or "").strip() + "\n", encoding="utf-8")
        pack = self._pack_from_files(meta_path, skill_path, editable=True)
        self._packs[pack.id] = pack
        return pack

    def update_local(self, skill_id: str, payload: dict[str, Any]) -> SkillPack:
        pack = self.get(skill_id)
        if pack is None:
            raise ValueError("Skill pack not found")
        if not pack.editable:
            raise ValueError("Built-in skill packs are read-only")
        directory = self.local_root / skill_id
        meta_path = directory / "metadata.yaml"
        skill_path = directory / "SKILL.md"
        existing = yaml.safe_load(meta_path.read_text(encoding="utf-8")) or {}
        version = int(payload.get("version") or int(existing.get("version", 1)) + 1)
        meta = self._metadata_from_payload(skill_id, {**existing, **payload}, version=version)
        meta_path.write_text(yaml.safe_dump(meta, sort_keys=False), encoding="utf-8")
        if "body" in payload:
            skill_path.write_text(str(payload.get("body") or "").strip() + "\n", encoding="utf-8")
        updated = self._pack_from_files(meta_path, skill_path, editable=True)
        self._packs[updated.id] = updated
        return updated

    def delete_local(self, skill_id: str) -> None:
        pack = self.get(skill_id)
        if pack is None:
            raise ValueError("Skill pack not found")
        if not pack.editable:
            raise ValueError("Built-in skill packs are read-only")
        directory = self.local_root / skill_id
        for path in sorted(directory.glob("**/*"), reverse=True):
            if path.is_file():
                path.unlink()
            elif path.is_dir():
                path.rmdir()
        if directory.exists():
            directory.rmdir()
        self._packs.pop(skill_id, None)

    def _normalize_id(self, raw: str) -> str:
        candidate = re.sub(r"[^a-z0-9_\\-]+", "_", raw.strip().lower())
        return candidate.strip("_")

    def _metadata_from_payload(self, skill_id: str, payload: dict[str, Any], *, version: int) -> dict[str, Any]:
        return {
            "id": skill_id,
            "name": str(payload.get("name") or skill_id.replace("_", " ").title()),
            "version": version,
            "summary": str(payload.get("summary") or ""),
            "roles": list(payload.get("roles") or ["orchestrator"]),
            "modes": list(payload.get("modes") or ["pentest"]),
            "execution_level": str(payload.get("execution_level") or "advisory"),
            "safety_level": str(payload.get("safety_level") or "active"),
            "tags": list(payload.get("tags") or []),
            "requires_scope": bool(payload.get("requires_scope", True)),
            "forbidden": list(payload.get("forbidden") or []),
        }


class SkillSelector:
    def __init__(self, registry: SkillRegistry | None = None) -> None:
        self.registry = registry or SkillRegistry()

    def select(self, run: WorkspaceRun, role: str, facts: list[Fact] | None = None) -> list[dict[str, Any]]:
        facts = facts or []
        selected: dict[str, str] = {}
        role_forced: set[str] = set()
        for skill_id in ROLE_DEFAULTS.get(role, []):
            selected[skill_id] = f"default for {role}"
            role_forced.add(skill_id)
        for skill_id in MODE_DEFAULTS.get(run.mode, []):
            selected.setdefault(skill_id, f"mode {run.mode}")
        haystack = " ".join([run.mode, run.objective or "", run.target or "", *[fact.kind + " " + fact.value for fact in facts]]).lower()
        for keywords, skill_id in KEYWORD_SKILLS:
            if any(word in haystack for word in keywords):
                selected.setdefault(skill_id, "matched run context or findings")
        out = []
        for skill_id, reason in selected.items():
            pack = self.registry.get(skill_id)
            if pack is None:
                continue
            if skill_id not in role_forced and run.mode not in pack.modes and role not in pack.roles:
                continue
            out.append(pack.public(reason=reason))
        return sorted(out, key=lambda item: item["id"])


class PromptAssembler:
    def __init__(self, registry: SkillRegistry | None = None) -> None:
        self.registry = registry or SkillRegistry()

    def assemble(self, run: WorkspaceRun, role: str, selected: list[dict[str, Any]], facts: list[Fact]) -> str:
        bodies = []
        for item in selected:
            pack = self.registry.get(str(item["id"]))
            if pack is not None:
                bodies.append(pack.body)
        facts_digest = [f"- {fact.kind}:{fact.source}:{fact.value}" for fact in facts[-12:]]
        focus = focus_from_facts(run, facts, role)
        lookup_guide = load_lookup_guide()
        return "\n".join(
            [
                "# Vantix Agent Prompt",
                f"role: {role}",
                f"mode: {run.mode}",
                f"target: {run.target}",
                f"objective: {run.objective}",
                f"focus: {focus}",
                "",
                "## Shared Policy",
                self.registry.shared_text(),
                "",
                "## Intelligence Lookup",
                lookup_guide,
                "",
                "## Recent Facts",
                "\n".join(facts_digest) or "- none",
                "",
                "## Selected Skills",
                "\n\n".join(bodies) or "No role-specific skills selected.",
                "",
                "## Output Contract",
                "Return dense JSON-compatible notes: obs, evidence, focus, loaded, risk, next, blocked, vectors.",
            ]
        )


class SkillApplicationService:
    def __init__(self) -> None:
        self.registry = SkillRegistry()
        self.selector = SkillSelector(self.registry)
        self.assembler = PromptAssembler(self.registry)
        self.storage = StorageLayout()
        self.events = RunEventService()

    def apply_to_run(self, db: Session, run: WorkspaceRun) -> list[dict[str, Any]]:
        facts = db.query(Fact).filter(Fact.run_id == run.id).order_by(Fact.created_at.asc()).all()
        agents = db.query(AgentSession).filter(AgentSession.run_id == run.id).all()
        provider_id = str((run.config_json or {}).get("provider_id") or "")
        provider = db.get(ProviderConfig, provider_id) if provider_id else None
        paths = self.storage.for_workspace(run.workspace_id)
        applications: list[dict[str, Any]] = []
        for agent in agents:
            selected = self.selector.select(run, agent.role, facts)
            metadata = dict(agent.metadata_json or {})
            metadata["selected_skills"] = selected
            metadata["skill_count"] = len(selected)
            metadata["runtime_route"] = {
                "runtime": "provider" if provider else "codex",
                "provider_id": provider.id if provider else "",
                "provider_type": provider.provider_type if provider else "",
                "provider_name": provider.name if provider else "",
            }
            metadata["default_runtime"] = provider.provider_type if provider else "codex"
            agent.metadata_json = metadata
            prompt = self.assembler.assemble(run, agent.role, selected, facts)
            prompt_path = paths.prompts / f"{agent.role}.txt"
            prompt_path.write_text(prompt, encoding="utf-8")
            agent.prompt_path = str(prompt_path)
            applications.append({"agent_role": agent.role, "skills": selected, "prompt_path": str(prompt_path)})
        self.events.emit(db, run.id, "skills", "Vantix skills applied", payload={"agents": applications})
        return applications

    def list_for_run(self, db: Session, run_id: str) -> list[dict[str, Any]]:
        agents = db.query(AgentSession).filter(AgentSession.run_id == run_id).order_by(AgentSession.role.asc()).all()
        return [
            {
                "agent_role": agent.role,
                "skills": list((agent.metadata_json or {}).get("selected_skills", [])),
                "prompt_path": agent.prompt_path,
            }
            for agent in agents
        ]


def list_attack_chains(db: Session, run_id: str) -> list[dict[str, Any]]:
    facts = db.query(Fact).filter(Fact.run_id == run_id, Fact.kind == "attack_chain").order_by(Fact.confidence.desc(), Fact.created_at.asc()).all()
    return [attack_chain_from_fact(fact) for fact in facts]


def attack_chain_from_fact(fact: Fact) -> dict[str, Any]:
    meta = fact.metadata_json or {}
    normalized_steps = []
    for step in list(meta.get("steps") or []):
        entry = dict(step)
        normalized_steps.append(
            {
                "name": str(entry.get("name") or entry.get("phase") or "step"),
                "preconditions": list(entry.get("preconditions") or []),
                "expected_outcome": str(entry.get("expected_outcome") or ""),
                "proof_required": list(entry.get("proof_required") or []),
                "stop_conditions": list(entry.get("stop_conditions") or []),
            }
        )
    return {
        "id": fact.id,
        "name": str(meta.get("name") or fact.value),
        "score": int(meta.get("score") or round((fact.confidence or 0) * 100)),
        "status": str(meta.get("status") or "identified"),
        "steps": normalized_steps,
        "mitre_ids": list(meta.get("mitre_ids") or []),
        "notes": str(meta.get("notes") or ""),
        "provenance": dict(meta.get("provenance") or {}),
        "created_at": fact.created_at,
    }


def create_attack_chain_fact(db: Session, run_id: str, payload: dict[str, Any]) -> Fact:
    score = int(payload.get("score") or 0)
    normalized_steps = []
    for step in list(payload.get("steps") or []):
        row = dict(step)
        normalized_steps.append(
            {
                "name": str(row.get("name") or row.get("phase") or "step"),
                "preconditions": list(row.get("preconditions") or []),
                "expected_outcome": str(row.get("expected_outcome") or ""),
                "proof_required": list(row.get("proof_required") or []),
                "stop_conditions": list(row.get("stop_conditions") or []),
            }
        )
    metadata = {
        "name": payload.get("name", "Attack chain"),
        "score": score,
        "status": payload.get("status", "identified"),
        "steps": normalized_steps,
        "mitre_ids": payload.get("mitre_ids", []),
        "notes": payload.get("notes", ""),
        "provenance": {
            "facts": list(payload.get("facts") or []),
            "cves": list(payload.get("cves") or []),
            "learning_hits": list(payload.get("learning_hits") or []),
            "operator_notes": list(payload.get("operator_notes") or []),
        },
    }
    fact = Fact(
        run_id=run_id,
        source="operator",
        kind="attack_chain",
        value=str(metadata["name"]),
        confidence=max(0.0, min(1.0, score / 100 if score else 0.5)),
        tags=["vantix", "attack_chain", str(metadata["status"])],
        metadata_json=metadata,
    )
    db.add(fact)
    db.flush()
    return fact


def build_handoff(db: Session, run: WorkspaceRun) -> dict[str, Any]:
    facts = db.query(Fact).filter(Fact.run_id == run.id).order_by(Fact.created_at.asc()).all()
    findings = db.query(Finding).filter(Finding.run_id == run.id).order_by(Finding.created_at.asc()).all()
    events = db.query(RunEvent).filter(RunEvent.run_id == run.id).order_by(RunEvent.sequence.desc()).limit(30).all()
    vectors = [fact for fact in facts if fact.kind == "vector"]
    services = [fact for fact in facts if fact.kind in {"service", "port", "host"}]
    blocked = [event.message for event in events if event.level in {"warning", "error"} or "blocked" in event.message.lower()]
    return {
        "run_id": run.id,
        "workspace_id": run.workspace_id,
        "mode": run.mode,
        "status": run.status,
        "target": run.target,
        "objective": run.objective,
        "scope": run.engagement.ruleset if run.engagement else "authorized-assessment",
        "phase": (events[0].event_type if events else "initialized"),
        "services": [{"kind": fact.kind, "value": fact.value, "source": fact.source, "confidence": fact.confidence} for fact in services],
        "vectors": [{"id": fact.id, "title": (fact.metadata_json or {}).get("title", fact.value), "status": (fact.metadata_json or {}).get("status", "candidate")} for fact in vectors],
        "validated_findings": [{"id": finding.id, "title": finding.title, "severity": finding.severity, "status": finding.status} for finding in findings if finding.status in {"validated", "confirmed"}],
        "blocked_items": blocked[:10],
        "attack_chains": list_attack_chains(db, run.id),
        "next_actions": _next_actions(run, vectors, findings, blocked),
    }


def _next_actions(run: WorkspaceRun, vectors: list[Fact], findings: list[Finding], blocked: list[str]) -> list[str]:
    if blocked:
        return ["resolve approval/blocker", "add operator guidance", "retry or replan"]
    if not vectors:
        return ["run recon", "load memory", "query CVE intel"]
    if not findings:
        return ["select highest-confidence vector", "run safe PoC validation", "store evidence"]
    return ["review validated findings", "generate report", "write close memory checkpoint"]
