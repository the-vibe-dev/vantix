from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path

from secops.config import settings


@dataclass(frozen=True)
class ScriptDefinition:
    id: str
    path: str
    modes: list[str]
    description: str

    def resolved_path(self) -> Path:
        return (settings.repo_root / self.path).resolve()

    def to_dict(self) -> dict:
        data = asdict(self)
        data["path"] = str(self.resolved_path())
        return data


SCRIPT_CATALOG: dict[str, ScriptDefinition] = {
    "codex_start": ScriptDefinition("codex_start", "scripts/codex-start.sh", ["ctf", "koth", "pentest", "bugbounty", "windows-ctf", "windows-koth"], "Session startup and learning digest bootstrap."),
    "codex_close": ScriptDefinition("codex_close", "scripts/codex-close.sh", ["ctf", "koth", "pentest", "bugbounty", "windows-ctf", "windows-koth"], "Session checkpoint, handoff, and close writer."),
    "learn_engine": ScriptDefinition("learn_engine", "scripts/learn_engine.py", ["ctf", "koth", "pentest", "bugbounty", "windows-ctf", "windows-koth"], "Structured learning and promotion engine."),
    "exploit_pipeline": ScriptDefinition("exploit_pipeline", "scripts/exploit-pipeline.sh", ["ctf", "koth", "pentest", "bugbounty"], "Version-to-CVE-to-PoC pipeline."),
    "source_audit": ScriptDefinition("source_audit", "scripts/source-audit.sh", ["pentest", "bugbounty"], "Source review and vuln pattern scanner."),
    "bugbounty_hunter": ScriptDefinition("bugbounty_hunter", "scripts/bugbounty-hunter.sh", ["bugbounty"], "Bug bounty orchestrator."),
    "binary_re": ScriptDefinition("binary_re", "scripts/binary-re.sh", ["ctf"], "Binary analysis pipeline."),
    "vpn_watch": ScriptDefinition("vpn_watch", "scripts/vpn-watch-start.sh", ["ctf", "koth", "pentest", "bugbounty", "windows-ctf", "windows-koth"], "VPN tunnel supervisor."),
    "koth_ops": ScriptDefinition("koth_ops", "scripts/kothholder.sh", ["koth", "windows-koth"], "KoTH hold helper; subject to rules enforcement."),
    "windows_ops": ScriptDefinition("windows_ops", "scripts/windows-enum.sh", ["windows-ctf", "windows-koth", "pentest"], "Windows enumeration helper."),
}
