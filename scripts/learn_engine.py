#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import shlex
import subprocess
import sys
import tempfile
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable


TEXT_EXTENSIONS = {
    ".md",
    ".txt",
    ".log",
    ".json",
    ".nmap",
    ".gnmap",
    ".xml",
    ".html",
    ".ldif",
    ".csv",
}
SCAN_EXTENSIONS = {".txt", ".log", ".nmap", ".gnmap", ".xml", ".json", ".html"}
SKIP_DIRS = {
    ".git",
    ".venv",
    ".venv_kp",
    "__pycache__",
    "@eaDir",
    "memory/learning",
    "memory/reports",
}
MAX_FILE_BYTES = 1_000_000
MAX_EVENTS_PER_FILE = 60
DENSE_CONTEXT_FILES = [
    "AGENTS.md",
    "MEM.md",
    "CLAUDE.md",
    "LOOKUP.md",
    "PENTEST.md",
    "USAGE.md",
    "methods/ctf/ctf_techniques.md",
    "methods/ctf/ctfplaybook.md",
    "methods/ctf/xss_replay_commands.md",
    "methods/linux/linux_privesc_extended.md",
    "methods/linux/service_attacks.md",
    "methods/network/pivoting_tunneling.md",
    "methods/thm_general/koth_playbook.md",
    "methods/thm_general/koth_replay_fireworks.md",
    "methods/web/version_source_research.md",
    "methods/web/web_vuln_playbook.md",
    "methods/windows/ad_enumeration.md",
    "methods/windows/windows_koth.md",
    "methods/windows/windows_pentest_playbook.md",
    "runbooks/workflow.md",
]

VECTOR_KEYWORDS = [
    ("auth bypass", "auth-bypass"),
    ("cmd injection", "cmd-injection"),
    ("command injection", "cmd-injection"),
    ("sqli", "sqli"),
    ("sql injection", "sqli"),
    ("ssrf", "ssrf"),
    ("lfi", "lfi"),
    ("rce", "rce"),
    ("xss", "xss"),
    ("upload bypass", "upload-bypass"),
    ("path hijack", "path-hijack"),
    ("pwnkit", "pwnkit"),
    ("pkexec", "pkexec"),
    ("anonymous ftp", "anon-ftp"),
    ("anon ftp", "anon-ftp"),
    ("sudo", "sudo"),
    ("suid", "suid"),
    ("private key", "private-key"),
    ("wp-config", "wp-config"),
    ("redirect", "redirect"),
    # KotH / shell-hold specific
    ("king-protect", "koth-defender"),
    ("bind mount", "bind-mount-defense"),
    ("preload hook", "ld-preload"),
    ("ld_preload", "ld-preload"),
    ("ld.so.preload", "ld-preload"),
    ("inotify", "fs-watch"),
    ("inotifywait", "fs-watch"),
    ("prctl", "process-rename"),
    # Opponent tunneling / shell tools
    ("chisel", "tunnel-tool"),
    ("ligolo", "tunnel-tool"),
    ("pwncat", "shell-tool"),
    ("socat", "relay-tool"),
    ("metasploit", "framework-tool"),
    ("msfvenom", "framework-tool"),
    # Binary RE / exploit research
    ("buffer overflow", "bof"),
    ("heap overflow", "heap-overflow"),
    ("use after free", "uaf"),
    ("format string", "fmt-string"),
    ("ret2libc", "ret2libc"),
    ("rop chain", "rop"),
    ("ghidra", "re-tool"),
    ("radare2", "re-tool"),
    # Windows / AD attacks
    ("ms17-010", "eternalblue"),
    ("eternalblue", "eternalblue"),
    ("pass the hash", "pass-the-hash"),
    ("pass-the-hash", "pass-the-hash"),
    ("pth", "pass-the-hash"),
    ("kerberoast", "kerberoast"),
    ("as-rep roast", "asrep-roast"),
    ("asreproast", "asrep-roast"),
    ("asrep roast", "asrep-roast"),
    ("dcsync", "dcsync"),
    ("golden ticket", "golden-ticket"),
    ("silver ticket", "silver-ticket"),
    ("ntlm relay", "ntlm-relay"),
    ("ntlmrelayx", "ntlm-relay"),
    ("responder", "ntlm-relay"),
    ("token impersonation", "token-impersonation"),
    ("seimpersonateprivilege", "token-impersonation"),
    ("godpotato", "token-impersonation"),
    ("printspoofer", "token-impersonation"),
    ("roguepotato", "token-impersonation"),
    ("juicypotato", "token-impersonation"),
    ("unquoted service", "unquoted-path"),
    ("alwaysinstallelevated", "alwaysinstallelevated"),
    ("dll hijack", "dll-hijack"),
    ("dll side-load", "dll-hijack"),
    ("uac bypass", "uac-bypass"),
    ("bloodhound", "bloodhound"),
    ("sharphound", "bloodhound"),
    ("powerview", "bloodhound"),
    ("mimikatz", "mimikatz"),
    ("sekurlsa", "mimikatz"),
    ("lsadump", "mimikatz"),
    ("rubeus", "kerberoast"),
    ("evil-winrm", "winrm-shell"),
    ("evilwinrm", "winrm-shell"),
    ("crackmapexec", "cme-enum"),
    ("netexec", "cme-enum"),
    ("impacket", "impacket"),
    ("psexec", "impacket"),
    ("wmiexec", "impacket"),
    ("secretsdump", "impacket"),
    ("petitpotam", "ntlm-coerce"),
    ("printerbug", "ntlm-coerce"),
    ("printernightmare", "printernightmare"),
    ("adcs", "adcs"),
    ("certipy", "adcs"),
    ("esc1", "adcs"),
    ("esc8", "adcs"),
    ("dpapi", "dpapi"),
    ("ntds.dit", "ntds-dump"),
    ("lsass", "lsass-dump"),
    ("procdump", "lsass-dump"),
    ("gpp-decrypt", "gpp-cpassword"),
    ("cpassword", "gpp-cpassword"),
    ("unconstrained delegation", "delegation-abuse"),
    ("constrained delegation", "delegation-abuse"),
    # Web attacks
    ("xxe", "xxe"),
    ("xml external entity", "xxe"),
    ("ssti", "ssti"),
    ("template injection", "ssti"),
    ("server-side template", "ssti"),
    ("deserialization", "deserialization"),
    ("ysoserial", "deserialization"),
    ("phpggc", "deserialization"),
    ("pickle rce", "deserialization"),
    ("unserialize", "deserialization"),
    ("insecure direct object", "idor"),
    ("cors misconfiguration", "cors"),
    ("access-control-allow-origin", "cors"),
    ("jwt attack", "jwt-attack"),
    ("alg:none", "jwt-attack"),
    ("rs256 hs256", "jwt-attack"),
    ("oauth bypass", "oauth-bypass"),
    ("redirect_uri", "oauth-bypass"),
    # Container escape
    ("docker escape", "container-escape"),
    ("privileged container", "container-escape"),
    ("docker.sock", "container-escape"),
    ("lxd privesc", "container-escape"),
    ("lxc privesc", "container-escape"),
    ("notify_on_release", "container-escape"),
    # Linux extended privesc
    ("pwnkit", "polkit"),
    ("cve-2021-4034", "polkit"),
    ("dirty pipe", "dirty-pipe"),
    ("cve-2022-0847", "dirty-pipe"),
    ("ld_preload", "ld-preload"),
    ("pam backdoor", "pam-persist"),
    ("pam_permit", "pam-persist"),
    ("no_root_squash", "nfs-squash"),
    # Service attacks
    ("redis rce", "redis-rce"),
    ("redis config set", "redis-rce"),
    ("nosql injection", "nosql-injection"),
    ("nosqli", "nosql-injection"),
    # Pivoting / tunneling
    ("chisel", "pivoting"),
    ("ligolo", "pivoting"),
    ("proxychains", "pivoting"),
    ("port forward", "pivoting"),
    ("socks proxy", "pivoting"),
    # CTF / steganography
    ("steganography", "steganography"),
    ("stegsolve", "steganography"),
    ("steghide", "steganography"),
    ("lsb steg", "steganography"),
    ("zsteg", "steganography"),
    # Bug bounty / H1 findings
    ("ssrf sheriff", "ssrf-confirmed"),
    ("ssrf-confirmed", "ssrf-confirmed"),
    ("idor confirmed", "idor"),
    ("subdomain takeover", "subdomain-takeover"),
    ("cname dangling", "subdomain-takeover"),
    ("oauth bypass", "oauth-bypass"),
    ("redirect_uri", "oauth-bypass"),
    ("jwt", "jwt-attack"),
    ("alg: none", "jwt-attack"),
    ("business logic", "business-logic"),
    ("price manipulation", "business-logic"),
    ("broken access control", "idor"),
]

EXPLOIT_VERBS = [
    "exploited",
    "used",
    "gained",
    "pivoted",
    "escalated",
    "recovered",
    "harvest",
    "dumped",
    "captured",
    "claimed",
    "pulled",
    "leveraged",
]

TAG_KEYWORDS = {
    "xss": ["xss", "cross-site scripting", "onerror", "onload", "onpageshow", "ontoggle",
            "alert(\"xss\")", "prompt(\"xss\")", "confirm(\"xss\")", "dalgona"],
    "koth": ["koth", "king.txt", ":9999", "hill", "claim", "holder", "kingguard"],
    "web": ["http", "php", "wordpress", "adminer", "wp-", "vhost", "web", "apache", "nginx",
            "xxe", "ssti", "template injection", "deserialization", "idor", "cors", "jwt",
            "oauth", "ssrf", "ysoserial", "phpggc", "nosql"],
    "windows": ["winrm", "secretsdump", "hash", "active directory", "smb", "rpc", "administrator",
                "crackmapexec", "netexec", "mimikatz", "rubeus", "bloodhound", "kerberoast",
                "golden ticket", "dcsync", "evil-winrm", "ms17-010", "eternalblue",
                "ntlm relay", "pass the hash", "seimpersonate", "godpotato", "printspoofer",
                "roguepotato", "juicypotato", "unquoted service", "alwaysinstallelevated",
                "dll hijack", "uac bypass", "adcs", "certipy", "ntds.dit", "lsass",
                "psexec", "wmiexec", "impacket", "petitpotam", "printernightmare"],
    "ad": ["active directory", "domain controller", "domain admin", "dc=", "bloodhound",
           "kerberoast", "dcsync", "golden ticket", "ntlm relay", "kerbrute",
           "sharphound", "powerview", "rubeus", "impacket", "adcs", "certipy",
           "ldap", "krbtgt", "spn", "delegation", "sysvol", "gpp", "cpassword"],
    "kerberos": ["kerberoast", "asreproast", "as-rep roast", "golden ticket", "silver ticket",
                 "rubeus", "tgt", "tgs", "spn", "kinit", "klist", "krbtgt",
                 "unconstrained delegation", "constrained delegation", "s4u2proxy"],
    "linux": ["sudo", "suid", "/etc/", "bash", "systemd", "pkexec", "pwnkit",
              "dirty pipe", "ld_preload", "pam_permit", "no_root_squash"],
    "container": ["docker", "lxd", "lxc", "privileged container", "docker.sock",
                  "container escape", "cgroup", "notify_on_release", "/.dockerenv"],
    "pivoting": ["chisel", "ligolo", "proxychains", "socat tunnel", "ssh -d",
                 "port forward", "socks proxy", "portproxy", "pivot"],
    "ctf": ["steganography", "stegsolve", "steghide", "zsteg", "binwalk", "foremost",
            "caesar", "vigenere", "rot13", "morse code", "ltrace", "ghidra",
            "padding oracle", "xor key", "hash extension"],
    "credential": ["password", "credential", "creds", "private key", "authorized_keys", "token"],
    "ssrf": ["ssrf", "redirect", "127.0.0.1", "file://"],
    "sqli": ["sqli", "sql injection"],
    "rce": ["rce", "cmd injection", "command injection"],
    "flap": ["flap", "flappy", "timeout", "filtered", "unstable", "vpn", "tunnel", "health check"],
    "tooling": ["script", "automation", "parser", "quote", "quoting", "nonce", "process count", "cli"],
    "opponent_tool": ["king-protect", "protectking", "claimed by", "bash loop", "while true",
                      "echo.*king", "chisel", "pwncat", "ligolo", "msfvenom", "kingkit",
                      "reverse shell", "c2", "callback", "beacon", "payload", "implant",
                      "dropper", "opponent", "adversary"],
    "opponent_tactic": ["crontab inject", "service install", "ld_preload", "ld.so.preload",
                        "bind mount", "immutable", "chattr", "authorized_keys wipe",
                        "king loop", "king-protect.service"],
    "exploit": ["cve-", "poc", "proof of concept", "metasploit", "exploit", "shellcode",
                "buffer overflow", "heap overflow", "use after free", "format string", "ret2libc"],
    "binary_re": ["ghidra", "radare2", " r2 ", "elf binary", "pe32", "strings output",
                  "readelf", "objdump", "entropy", "packed", "upx"],
    "bug_bounty": ["hackerone", "h1", "bug bounty", "ssrf sheriff", "idor confirmed",
                   "subdomain takeover", "cvss", "bounty", "@wearehackerone.com",
                   "out-of-scope", "in-scope", "proof of concept", "impact bucket"],
}

SOURCE_BASE_CONFIDENCE = {
    "retro": 0.92,
    "lesson": 0.95,
    "training": 0.95,
    "session_memory": 0.78,
    "challenge_note": 0.76,
    "scan": 0.55,
    "log": 0.45,
    "artifact": 0.52,
    "generic": 0.58,
    "opponent_tool": 0.72,        # extracted from opponent artifacts on KotH/CTF targets
    "exploit_result": 0.88,       # confirmed successful PoC/exploit run
    "bug_bounty_finding": 0.95,   # confirmed H1 bug bounty finding with PoC
}

HEADING_BONUS = {
    "what worked": 0.10,
    "what went wrong": 0.08,
    "better next time": 0.12,
    "methodology updates needed": 0.15,
    "reusable commands/scripts": 0.08,
    "clues missed early": 0.08,
    "tunnel/infra notes": 0.07,
    "verification check": 0.14,
    "corrective guardrail": 0.14,
}

# ─── LLM configuration (codex exec) ─────────────────────────────────────────

LLM_MODELS = {
    "classify":     "gpt-5.1-codex",   # cheapest — bulk ingest classification
    "dedup":        "gpt-5.1-codex",   # cheapest — signature comparison
    "consolidate":  "gpt-5.2-codex",   # mid — compact merge analysis
    "promote":      "gpt-5.3-codex",   # best — methodology drafting
    "summarize":    "gpt-5.1-codex",   # cheapest — journal compaction
}

LLM_BATCH_SIZE = {
    "classify": 30,
    "dedup": 40,
    "consolidate": 50,
    "promote": 10,
}


def _find_codex() -> str | None:
    """Return path to codex CLI or None if unavailable."""
    for candidate in [shutil.which("codex")]:
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def llm_call(task: str, prompt: str, stdin_text: str, timeout_seconds: int = 120) -> str | None:
    """Call codex exec with prompt and stdin. Returns output text or None on failure."""
    codex = _find_codex()
    if codex is None:
        return None
    model = LLM_MODELS.get(task, "gpt-5.1-codex")
    fd, output_file = tempfile.mkstemp(suffix=".txt")
    os.close(fd)
    try:
        result = subprocess.run(
            [codex, "exec", "-m", model, "--ephemeral", "--skip-git-repo-check",
             "-s", "read-only", "-o", output_file, prompt],
            input=stdin_text, capture_output=True, text=True, timeout=timeout_seconds,
        )
        output_path = Path(output_file)
        if result.returncode == 0 and output_path.exists() and output_path.stat().st_size > 0:
            return output_path.read_text(encoding="utf-8", errors="ignore")
        return None
    except (subprocess.TimeoutExpired, OSError):
        return None
    finally:
        try:
            os.unlink(output_file)
        except OSError:
            pass


def _parse_llm_jsonl(text: str) -> list[dict]:
    """Parse LLM output as JSONL, tolerant of markdown fences and extra text."""
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("```"):
            continue
        if not line or not line.startswith("{"):
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


@dataclass
class Event:
    event_id: str
    ts: str
    source_path: str
    source_kind: str
    category: str
    title: str
    summary: str
    heading: str
    tags: list[str]
    target_class: list[str]
    preconditions: str
    action_pattern: str
    verification_signal: str
    impact: str
    confidence: float
    novelty: float
    status: str
    promote_target: str
    draft_text: str
    signature: str
    ports: list[str] | None = None
    services: list[str] | None = None
    cves: list[str] | None = None


def now_utc() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def jsonl_load(path: Path) -> list[dict]:
    if not path.exists() or path.stat().st_size == 0:
        return []
    rows = []
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


COMPACT_SKIP_FIELDS = {"draft_text"}
COMPACT_SKIP_IF_DEFAULT = {"preconditions": "", "verification_signal": "", "action_pattern": ""}
CTF_ROOT_PREFIX = str(Path.cwd()) + "/"


def compact_entry(entry: dict) -> dict:
    """Strip heavy/redundant fields from canonical entries to reduce token weight."""
    out = {}
    for k, v in entry.items():
        if k in COMPACT_SKIP_FIELDS:
            continue
        if k in COMPACT_SKIP_IF_DEFAULT and v == COMPACT_SKIP_IF_DEFAULT[k]:
            continue
        if k == "signature" and isinstance(v, str) and len(v) > 32:
            v = v[:32]
        if k == "source_paths" and isinstance(v, list):
            v = [p.replace(CTF_ROOT_PREFIX, "") if isinstance(p, str) else p for p in v]
        out[k] = v
    return out


def jsonl_write(path: Path, rows: Iterable[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=False) + "\n")


def jsonl_append(path: Path, rows: Iterable[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=False) + "\n")


def read_text(path: Path) -> str:
    if path.stat().st_size > MAX_FILE_BYTES:
        return ""
    sample = path.read_bytes()[:4096]
    if b"\x00" in sample:
        return ""
    return path.read_text(encoding="utf-8", errors="ignore")


def normalize_space(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip())


def slugify(text: str) -> str:
    text = text.lower()
    text = re.sub(r"`+", "", text)
    text = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "<ip>", text)
    text = re.sub(r"thm\{[^}]+\}", "thm-flag", text)
    text = re.sub(r"0x[0-9a-f]+", "hex", text)
    text = re.sub(r"[^a-z0-9]+", "-", text).strip("-")
    return re.sub(r"-{2,}", "-", text)


def classify_source(path: Path, root: Path) -> str:
    rel = path.relative_to(root).as_posix()
    if rel.endswith("SESSION_LESSONS.md") or rel.endswith("session-retro-template.md"):
        return "retro"
    if rel.endswith("memory/lessons_learned.md"):
        return "lesson"
    if rel.endswith("memory/training_notes.md"):
        return "training"
    if rel.startswith("memory/sessions/") or rel.endswith("memory/session_journal.md") or rel.endswith("memory/compaction_handoffs.md"):
        return "session_memory"
    if rel.startswith("memory/opponent_tools/"):
        return "opponent_tool"
    if rel.startswith("memory/bugbounty/"):
        return "bug_bounty_finding"
    if rel.startswith("challenges/") and path.suffix.lower() in {".md", ".txt", ".log"}:
        return "challenge_note"
    if rel.startswith("scans/"):
        return "scan"
    if rel.endswith(".log") or "watch" in path.name.lower() or "supervisor" in path.name.lower():
        return "log"
    if "exploit_result" in path.name.lower() or "exploit-result" in path.name.lower():
        return "exploit_result"
    if rel.startswith("artifacts/") or rel.startswith("tmp/"):
        return "artifact"
    return "generic"


def should_scan_file(path: Path, root: Path) -> bool:
    rel = path.relative_to(root).as_posix()
    for skip in SKIP_DIRS:
        if rel.startswith(skip + "/") or rel == skip:
            return False
    if path.suffix.lower() not in TEXT_EXTENSIONS and path.name not in {
        "session_journal.md",
        "compaction_handoffs.md",
        "SESSION_LESSONS.md",
        "lessons_learned.md",
        "training_notes.md",
    }:
        return False
    return path.is_file()


def discover_paths(root: Path, source_paths: list[str]) -> list[Path]:
    if source_paths:
        resolved = []
        for raw in source_paths:
            path = Path(raw)
            if not path.is_absolute():
                path = root / raw
            if path.exists() and path.is_file():
                resolved.append(path)
        return sorted(set(resolved))

    scan_roots = [
        root / "memory",
        root / "notes",
        root / "challenges",
        root / "scans",
        root / "artifacts",
        root / "tmp",
        root / "memory" / "opponent_tools",
        root / "memory" / "bugbounty",
    ]
    found: list[Path] = []
    for scan_root in scan_roots:
        if not scan_root.exists():
            continue
        for path in scan_root.rglob("*"):
            if should_scan_file(path, root):
                found.append(path)
    return sorted(set(found))


def infer_tags(path: Path, heading: str, summary: str) -> tuple[list[str], list[str]]:
    haystack = f"{path.as_posix()} {heading} {summary}".lower()
    tags = set()
    target_class = set()
    for tag, keywords in TAG_KEYWORDS.items():
        if any(keyword in haystack for keyword in keywords):
            tags.add(tag)
            target_class.add(tag)
    if "koth" in tags:
        target_class.add("linux")
    if "web" in tags and "rce" in tags:
        target_class.add("web")
    return sorted(tags), sorted(target_class)


def detect_vector_tokens(summary: str) -> list[str]:
    text = summary.lower()
    tokens = []
    for keyword, token in VECTOR_KEYWORDS:
        if keyword in text:
            tokens.append(token)
    return sorted(set(tokens))


SERVICE_KEYWORDS = {
    "apache": ["apache", "httpd", "mod_proxy", "mod_cgi"],
    "nginx": ["nginx"],
    "wordpress": ["wordpress", "wp-", "wpscan", "xmlrpc"],
    "openssh": ["openssh", "sshd"],
    "smb": ["smb", "samba", "cifs"],
    "mysql": ["mysql", "mariadb"],
    "ftp": ["ftp", "vsftpd", "proftpd"],
    "redis": ["redis"],
    "tomcat": ["tomcat", "catalina"],
    "iis": ["iis", "aspx", "asp.net"],
    "postgresql": ["postgresql", "postgres", "psql"],
    "ldap": ["ldap", "ldapsearch"],
    "dns": ["dns", "bind9", "named"],
    "snmp": ["snmp", "snmpwalk"],
    "winrm": ["winrm", "evil-winrm"],
    "rdp": ["xfreerdp", "rdesktop", "rdp ", " rdp", "rdp:", ":3389"],
    "nfs": ["nfs", "showmount", "no_root_squash"],
    "docker": ["docker", "docker.sock", "dockerd"],
    "jenkins": ["jenkins"],
    "gitlab": ["gitlab"],
    "grafana": ["grafana"],
    "adminer": ["adminer"],
    "phpmyadmin": ["phpmyadmin"],
}

PORT_IMPLICIT = {
    "ssh": "22", "http": "80", "https": "443", "smb": "445",
    "ftp": "21", "mysql": "3306", "redis": "6379", "rdp": "3389",
    "dns": "53", "snmp": "161", "ldap": "389", "nfs": "2049",
    "winrm": "5985", "postgresql": "5432",
}

_PORT_RE = re.compile(r"(?:(?:^|\s)(\d{2,5})/(?:open|tcp|udp)|\bport\s+(\d{1,5})\b|:(\d{3,5})\b)", re.IGNORECASE)
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


_COMMON_PORTS = frozenset({
    20, 21, 22, 23, 25, 53, 69, 80, 81, 82, 88, 110, 111, 135, 139, 143,
    161, 389, 443, 445, 464, 514, 587, 623, 636, 993, 995, 1080, 1099,
    1433, 1434, 1521, 1883, 2049, 2181, 2222, 3000, 3128, 3306, 3389,
    4443, 4444, 5000, 5432, 5555, 5900, 5985, 5986, 6379, 6443, 7443,
    8000, 8001, 8002, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 9200,
    9443, 9999, 10000, 10250, 11211, 27017, 31337, 50000,
})

def extract_ports(text: str) -> list[str]:
    found: set[str] = set()
    for m in _PORT_RE.finditer(text):
        port_str = m.group(1) or m.group(2) or m.group(3)
        if port_str:
            port = int(port_str)
            if port in _COMMON_PORTS:
                found.add(str(port))
    lower = text.lower()
    for keyword, port in PORT_IMPLICIT.items():
        if keyword in lower:
            found.add(port)
    return sorted(found, key=int)


def extract_services(text: str) -> list[str]:
    lower = text.lower()
    found: set[str] = set()
    for svc, keywords in SERVICE_KEYWORDS.items():
        if any(kw in lower for kw in keywords):
            found.add(svc)
    return sorted(found)


def extract_cves(text: str) -> list[str]:
    return sorted({m.group(0).upper() for m in _CVE_RE.finditer(text)})


def classify_category(source_kind: str, heading: str, summary: str) -> str | None:
    text = summary.lower()
    head = heading.lower()
    if not summary:
        return None
    if len(summary) < 16:
        return None
    if re.match(r"^(date|source|operator|target/room|ip|completed|flags/proofs captured|pentes[t]?\.md updates|pentes[t]?_improved\.md updates):", text):
        return None
    if "summary appended to" in text:
        return None
    # Nmap boilerplate and scan noise
    if re.search(r"(service detection performed|please report any incorrect results|nmap done|nmap scan report for|not shown:.*closed|host is up \()", text):
        return None
    # Session journal metadata lines (ephemeral state, not learning)
    if re.match(r"^(blockers?|next step|actions? taken|files? changed|mode|session id|alias|agent id|phase|context tags|goal|classification|event ts):", text):
        return None
    # Raw nmap port lines without context
    if re.match(r"^\d+/(tcp|udp)\s+(open|filtered|closed)", text):
        return None
    if source_kind == "opponent_tool":
        # Filter noise from tool-extractor reports (strings output, report boilerplate, IOCs, metadata)
        if len(summary) < 40:
            return None
        # Report structure lines
        if re.match(r"^(session:|target:|ts:|operator:|type:|sha256:|size:|identified_families:|suspected_family:)", text):
            return None
        # Strings output, flags, man-page fragments
        if re.match(r"^(\*\*notable|sock |https?://|report any |unknown system|gnu |--[a-z]|-[A-Za-z],)", text):
            return None
        if re.search(r"(standard output is connected|ls_colors environment|kibibytes default|shell pattern|implied entries)", text):
            return None
        # Network IOC listing
        if re.match(r"^\*\*(network iocs?|counter-technique)", text):
            return None
        # Binary analysis metadata
        if re.match(r"^(elf |pe32|entry point|dynamic imports|packed section)", text):
            return None
        # Report boilerplate about what the report does
        if re.search(r"(maps to a counter-technique in this report|gives us their .* patterns|run learn_engine|absorb this report)", text):
            return None
        # Only keep lines that describe actual opponent behavior or counter-techniques
        if not re.search(r"(opponent|counter.?technique|tactic|persistence|hold pattern|defend|backdoor|c2 |reverse shell|king.?protect|service.?loop|cron.?inject|rootkit|ld.?preload|bind.?mount|immutable)", text):
            return None
        return "opponent_tool"
    if source_kind == "exploit_result":
        return "vector"
    if source_kind == "bug_bounty_finding":
        return "bug_bounty"
    if source_kind in {"scan", "log"} and not re.search(r"(rce|lfi|ssrf|sqli|xss|timeout|flap|unstable|filtered|eperm|bad file descriptor|king|loss|regain|sudo|suid|pkexec|path hijack|auth bypass|private key|nonce|quoting|parser)", text):
        return None
    vectorish = bool(detect_vector_tokens(summary) or re.search(r"\b(" + "|".join(EXPLOIT_VERBS) + r")\b", text))
    if "verification check" in head or re.search(r"\b(verify|verified|confirm|confirmed|returns|revalidated|proof)\b", text):
        if "pentest.md" in text or "methodology constraints" in text:
            return "guardrail"
        return "verification_rule"
    if "better next time" in head or "corrective guardrail" in head or "training notes" in head:
        return "guardrail"
    if "clues missed early" in head or "false assumption" in text or "dead-end" in text or "dead end" in text:
        return "false_lead"
    if "what went wrong" in head or "mistake pattern" in head:
        if re.search(r"\b(script|automation|parser|nonce|quoting|process count|cli|holder)\b", text):
            return "tooling_failure"
        if re.search(r"\b(timeout|flap|unstable|filtered|vpn|tunnel|health check)\b", text):
            return "stability_issue"
        return "bug"
    if "tunnel/infra notes" in head or re.search(r"\b(timeout|flap|unstable|filtered|vpn|tunnel|health check)\b", text):
        return "stability_issue"
    if "reusable commands/scripts" in head:
        return "vector"
    if "what worked" in head:
        return "vector" if vectorish else "guardrail"
    if detect_vector_tokens(summary):
        return "vector"
    if source_kind == "training":
        return "guardrail"
    if re.search(r"\b(always|never|immediately|do not|keep|prefer|after first|before broad|strict order)\b", text):
        return "guardrail"
    if re.search(r"\b(failed|wrong|incorrect|missed|stalled|fixation|brittle|blocked|assumed)\b", text):
        if re.search(r"\b(script|automation|parser|nonce|quoting|process count|cli)\b", text):
            return "tooling_failure"
        return "bug"
    return None


def extract_preconditions(summary: str) -> str:
    match = re.search(r"\b(?:if|when|after|once)\b(.+?)(?:,|;| then |\.)", summary, re.IGNORECASE)
    return normalize_space(match.group(0)) if match else ""


def extract_action_pattern(summary: str) -> str:
    commands = re.findall(r"`([^`]+)`", summary)
    if commands:
        return normalize_space(commands[0])
    vector_tokens = detect_vector_tokens(summary)
    if vector_tokens:
        return ",".join(vector_tokens)
    return ""


def extract_verification_signal(summary: str) -> str:
    match = re.search(r"\b(?:verify|confirm|confirmed|returns|proof|revalidated)\b(.+?)(?:\.|$)", summary, re.IGNORECASE)
    return normalize_space(match.group(0)) if match else ""


def impact_for(category: str) -> str:
    if category == "vector":
        return "access"
    if category in {"guardrail", "verification_rule"}:
        return "quality"
    if category in {"tooling_failure", "stability_issue"}:
        return "reliability"
    if category == "opponent_tool":
        return "intelligence"
    if category == "attack_technique":
        return "intelligence"
    if category == "bug_bounty":
        return "bounty"
    return "learning"


def base_confidence(source_kind: str, heading: str, summary: str) -> float:
    score = SOURCE_BASE_CONFIDENCE.get(source_kind, 0.58)
    head = heading.lower()
    for marker, bonus in HEADING_BONUS.items():
        if marker in head:
            score += bonus
    if "`" in summary or "THM{" in summary or "CVE-" in summary:
        score += 0.05
    if re.search(r"\b(verified|confirmed|proof|revalidated|captured)\b", summary, re.IGNORECASE):
        score += 0.06
    if source_kind in {"scan", "log"}:
        score -= 0.06
    return max(0.25, min(0.99, round(score, 2)))


def pick_promote_target(category: str, tags: list[str], confidence: float, occurrences: int) -> str:
    if "koth" in tags:
        if category in {"guardrail", "verification_rule", "vector", "opponent_tool"} and confidence >= 0.82:
            return "koth_playbook.md"
    if category in {"guardrail", "verification_rule"}:
        if confidence >= 0.88 and occurrences >= 2:
            return "PENTEST.md"
        if confidence >= 0.80:
            return "training_notes.md"
    if category == "vector":
        if confidence >= 0.88 and occurrences >= 2:
            return "PENTEST.md"
        return "lessons_learned.md"
    if category in {"opponent_tool", "attack_technique"}:
        if confidence >= 0.80 and occurrences >= 2:
            return "PENTEST.md"
        return "lessons_learned.md"
    if category == "bug_bounty":
        if confidence >= 0.92 and occurrences >= 1:
            return "PENTEST.md"
        return "lessons_learned.md"
    if category in {"tooling_failure", "stability_issue"}:
        return "lessons_learned.md"
    if category in {"bug", "false_lead"}:
        return "lessons_learned.md"
    return ""


def draft_for(title: str, summary: str, category: str, promote_target: str, verification_signal: str) -> str:
    if promote_target == "training_notes.md":
        return f"- {summary}"
    if category in {"guardrail", "verification_rule"}:
        body = [
            f"### {title}",
            f"- Corrective guardrail: {summary}",
        ]
        if verification_signal:
            body.append(f"- Verification check: {verification_signal}")
        return "\n".join(body)
    if category == "vector":
        return "\n".join(
            [
                f"### {title}",
                f"- Reusable vector: {summary}",
                f"- Verification signal: {verification_signal or 'Record a concrete proof marker before broadening enumeration.'}",
            ]
        )
    return "\n".join(
        [
            f"### {title}",
            f"- Mistake pattern: {summary}",
            f"- Verification check: {verification_signal or 'Repeat only with a bounded, evidence-backed check.'}",
        ]
    )


def summarize_title(summary: str, category: str) -> str:
    tokens = detect_vector_tokens(summary)
    if tokens:
        label = tokens[0].replace("-", " ").upper()
        return f"{label}: {normalize_space(summary)[:72]}"
    if category == "stability_issue":
        return f"Stability: {normalize_space(summary)[:72]}"
    if category == "tooling_failure":
        return f"Tooling: {normalize_space(summary)[:72]}"
    if category == "guardrail":
        return f"Guardrail: {normalize_space(summary)[:72]}"
    return normalize_space(summary)[:84]


def build_signature(category: str, title: str, summary: str, tags: list[str]) -> str:
    normalized = slugify(f"{category} {' '.join(tags)} {title} {summary}")
    return normalized[:180]


def event_id_for(source_path: str, heading: str, summary: str, category: str) -> str:
    raw = f"{source_path}|{heading}|{summary}|{category}"
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


def extract_events_from_markdown(root: Path, path: Path, text: str) -> list[Event]:
    source_kind = classify_source(path, root)
    heading = ""
    events: list[Event] = []
    prefixes = [
        "mistake pattern:",
        "why it happened:",
        "corrective guardrail:",
        "verification check:",
    ]
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("#"):
            heading = line.lstrip("#").strip()
            continue
        if line.startswith(("```", "---")):
            continue
        if line.startswith(("- ", "* ")):
            line = line[2:].strip()
        else:
            numbered = re.match(r"^\d+\.\s+(.*)$", line)
            if numbered:
                line = numbered.group(1).strip()
        line = normalize_space(line)
        if line.startswith("[ ] "):
            line = line[4:].strip()
        for prefix in prefixes:
            if line.lower().startswith(prefix):
                line = line[len(prefix):].strip()
                break
        if not line:
            continue
        category = classify_category(source_kind, heading, line)
        if not category:
            continue
        tags, target_class = infer_tags(path, heading, line)
        title = summarize_title(line, category)
        confidence = base_confidence(source_kind, heading, line)
        promote_target = pick_promote_target(category, tags, confidence, 1)
        haystack = f"{path.as_posix()} {heading} {line}"
        event = Event(
            event_id=event_id_for(path.relative_to(root).as_posix(), heading, line, category),
            ts=now_utc(),
            source_path=path.relative_to(root).as_posix(),
            source_kind=source_kind,
            category=category,
            title=title,
            summary=line,
            heading=heading,
            tags=tags,
            target_class=target_class,
            preconditions=extract_preconditions(line),
            action_pattern=extract_action_pattern(line),
            verification_signal=extract_verification_signal(line),
            impact=impact_for(category),
            confidence=confidence,
            novelty=1.0,
            status="candidate" if confidence >= 0.75 else "observed",
            promote_target=promote_target,
            draft_text=draft_for(title, line, category, promote_target, extract_verification_signal(line)),
            signature=build_signature(category, title, line, tags),
            ports=extract_ports(haystack),
            services=extract_services(haystack),
            cves=extract_cves(haystack),
        )
        events.append(event)
        if len(events) >= MAX_EVENTS_PER_FILE:
            break
    return events


def extract_events(root: Path, path: Path) -> list[Event]:
    text = read_text(path)
    if not text:
        return []
    return extract_events_from_markdown(root, path, text)


def canonicalize(events: list[dict], no_llm: bool = False) -> tuple[list[dict], list[dict], list[dict], list[dict]]:
    grouped: dict[str, list[dict]] = defaultdict(list)
    for event in events:
        grouped[event["signature"]].append(event)

    # LLM semantic dedup: merge singletons that are semantically equivalent
    for merge_sig, into_sig in llm_find_dupes(grouped, no_llm=no_llm):
        if merge_sig in grouped and into_sig in grouped:
            grouped[into_sig].extend(grouped.pop(merge_sig))

    vectors: list[dict] = []
    bugs: list[dict] = []
    guardrails: list[dict] = []
    review_queue: list[dict] = []

    for signature, group in grouped.items():
        group.sort(key=lambda item: item["confidence"], reverse=True)
        best = dict(group[0])
        occurrences = len(group)
        confidence = min(0.99, round(best["confidence"] + min(0.18, 0.05 * (occurrences - 1)), 2))
        novelty = round(1.0 / occurrences, 2)
        tags = sorted({tag for item in group for tag in item.get("tags", [])})
        target_class = sorted({tag for item in group for tag in item.get("target_class", [])})
        ports = sorted({p for item in group for p in item.get("ports", [])}, key=lambda x: int(x) if x.isdigit() else 0)
        services = sorted({s for item in group for s in item.get("services", [])})
        cves = sorted({c for item in group for c in item.get("cves", [])})
        source_paths = sorted({item["source_path"] for item in group})
        source_kinds = sorted({item["source_kind"] for item in group})
        promote_target = pick_promote_target(best["category"], tags, confidence, occurrences)
        canonical = {
            "canonical_id": hashlib.sha1(signature.encode("utf-8")).hexdigest()[:16],
            "category": best["category"],
            "title": best["title"],
            "summary": best["summary"],
            "tags": tags,
            "target_class": target_class,
            "preconditions": best.get("preconditions", ""),
            "action_pattern": best.get("action_pattern", ""),
            "verification_signal": best.get("verification_signal", ""),
            "impact": best["impact"],
            "confidence": confidence,
            "novelty": novelty,
            "status": "candidate" if confidence >= 0.75 else "observed",
            "promote_target": promote_target,
            "draft_text": draft_for(best["title"], best["summary"], best["category"], promote_target, best.get("verification_signal", "")),
            "occurrences": occurrences,
            "source_paths": source_paths,
            "source_kinds": source_kinds,
            "ports": ports,
            "services": services,
            "cves": cves,
            "signature": signature,
        }
        compacted = compact_entry(canonical)
        if canonical["category"] == "vector":
            vectors.append(compacted)
        elif canonical["category"] in {"guardrail", "verification_rule"}:
            guardrails.append(compacted)
        elif canonical["category"] in {"opponent_tool", "attack_technique"}:
            # Intelligence items go into vectors (as counter-technique candidates)
            vectors.append(compacted)
        else:
            bugs.append(compacted)
        if canonical["status"] == "candidate" and promote_target and set(source_kinds) - {"lesson", "training"}:
            review_queue.append(
                compact_entry({
                    **canonical,
                    "queue_id": canonical["canonical_id"],
                    "review_reason": f"confidence={confidence}, occurrences={occurrences}, target={promote_target}",
                })
            )

    sorter = lambda item: (-item["confidence"], -item["occurrences"], item["title"])
    vectors.sort(key=sorter)
    bugs.sort(key=sorter)
    guardrails.sort(key=sorter)
    review_queue.sort(key=sorter)
    return vectors, bugs, guardrails, review_queue


_OPPONENT_FAMILY_PATTERNS = [
    ("king-protect", "flag-defender"), ("protectking", "flag-defender"),
    ("king loop", "flag-defender"), ("king.service", "flag-defender"),
    ("chisel", "tunnel-tool"), ("ligolo", "tunnel-tool"),
    ("pwncat", "shell-tool"), ("socat", "relay-tool"),
    ("ncat", "relay-tool"), ("netcat", "relay-tool"),
    ("msfvenom", "framework-tool"), ("metasploit", "framework-tool"),
    ("mimikatz", "cred-dumper"), ("lazagne", "cred-dumper"),
    ("linpeas", "enum-tool"), ("winpeas", "enum-tool"),
    ("linenum", "enum-tool"), ("linux-exploit-suggester", "enum-tool"),
    ("dirty_cow", "kernel-exploit"), ("dirtypipe", "kernel-exploit"),
    ("kingkit", "rootkit"), ("ld.so.preload", "rootkit"), ("ld_preload", "rootkit"),
    ("bind mount", "fs-trick"), ("bind-mount", "fs-trick"),
    ("reverse shell", "shell-tool"), ("bash -i", "shell-tool"),
    ("crontab", "persistence"), ("authorized_keys", "persistence"),
]


def _extract_opponent_family(entry: dict) -> str:
    text = f"{entry.get('title', '')} {entry.get('summary', '')}".lower()
    for keyword, family in _OPPONENT_FAMILY_PATTERNS:
        if keyword in text:
            return family
    return ""


def parse_dense_record(line: str, *, source_path: str = "") -> dict[str, Any] | None:
    line = line.strip()
    if not line or line.startswith("#") or line.startswith("fmt:") or line.startswith("load:"):
        return None
    if "id=" not in line:
        return None
    try:
        parts = shlex.split(line)
    except ValueError:
        parts = line.split()
    record: dict[str, Any] = {"source_path": source_path, "category": "playbook"}
    for part in parts:
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        record[key] = value
    if not record.get("id"):
        return None
    for key in ("mode", "role", "tags", "ports", "svc"):
        raw = str(record.get(key, ""))
        if raw in {"", "*"}:
            record[key] = []
        else:
            record[key] = [item for item in raw.split(",") if item and item != "*"]
    return record


def dense_record_summary(record: dict[str, Any]) -> str:
    fields = []
    keys = ("trigger", "cmd", "use", "next", "block") if record.get("cmd") or record.get("trigger") else ("pre", "act", "verify", "next", "block")
    for key in keys:
        value = str(record.get(key, "")).strip()
        if value and value != "*":
            fields.append(f"{key}={value}")
    return " ".join(fields)[:320]


def load_dense_playbook_records(root: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for rel in DENSE_CONTEXT_FILES:
        path = root / rel
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            record = parse_dense_record(line, source_path=rel)
            if record is not None:
                records.append(record)
    return records


def build_index(learning_dir: Path, all_canonical: list[dict]) -> None:
    root = learning_dir.parents[1]
    dense_records = load_dense_playbook_records(root)
    index: dict = {
        "meta": {"built": now_utc(), "entry_count": len(all_canonical) + len(dense_records), "dense_playbooks": len(dense_records)},
        "by_tag": {},
        "by_port": {},
        "by_service": {},
        "by_cve": {},
        "by_mode": {},
        "by_phase": {},
        "by_role": {},
        "by_opponent_family": {},
        "entries": {},
    }
    for entry in all_canonical:
        cid = entry.get("canonical_id", entry.get("event_id", ""))
        if not cid:
            continue
        for tag in entry.get("tags", []):
            index["by_tag"].setdefault(tag, []).append(cid)
        for port in entry.get("ports", []):
            index["by_port"].setdefault(port, []).append(cid)
        for svc in entry.get("services", []):
            index["by_service"].setdefault(svc, []).append(cid)
        for cve in entry.get("cves", []):
            index["by_cve"].setdefault(cve, []).append(cid)
        # Opponent family extraction from title/tags/category
        entry_tags = set(entry.get("tags", []))
        is_opponent = (
            entry.get("category") in ("opponent_tool", "attack_technique")
            or "opponent_tool" in entry_tags
            or "opponent_tactic" in entry_tags
        )
        if is_opponent:
            family = _extract_opponent_family(entry)
            if family:
                index["by_opponent_family"].setdefault(family, []).append(cid)
        index["entries"][cid] = {
            "title": entry.get("title", ""),
            "category": entry.get("category", ""),
            "confidence": entry.get("confidence", 0),
            "tags": entry.get("tags", []),
            "ports": entry.get("ports", []),
            "services": entry.get("services", []),
            "summary_short": entry.get("summary", "")[:120],
        }
    for record in dense_records:
        cid = f"playbook:{record['id']}"
        for tag in record.get("tags", []):
            index["by_tag"].setdefault(tag, []).append(cid)
        for port in record.get("ports", []):
            index["by_port"].setdefault(port, []).append(cid)
        for svc in record.get("svc", []):
            index["by_service"].setdefault(svc, []).append(cid)
        for mode in record.get("mode", []):
            index["by_mode"].setdefault(mode, []).append(cid)
        phase = str(record.get("phase", ""))
        if phase and phase != "*":
            index["by_phase"].setdefault(phase, []).append(cid)
        for role in record.get("role", []):
            index["by_role"].setdefault(role, []).append(cid)
        title = str(record.get("id", cid))
        index["entries"][cid] = {
            "title": title,
            "category": "playbook",
            "confidence": 1.0,
            "tags": record.get("tags", []),
            "ports": record.get("ports", []),
            "services": record.get("svc", []),
            "modes": record.get("mode", []),
            "phase": phase,
            "roles": record.get("role", []),
            "summary_short": dense_record_summary(record),
            "source_path": record.get("source_path", ""),
        }
    # Deduplicate ID lists in inverted indices
    for bucket_name in ("by_tag", "by_port", "by_service", "by_cve", "by_mode", "by_phase", "by_role", "by_opponent_family"):
        for key in index[bucket_name]:
            index[bucket_name][key] = sorted(set(index[bucket_name][key]))
    tmp = learning_dir / "index.json.tmp"
    tmp.write_text(json.dumps(index, separators=(",", ":")), encoding="utf-8")
    tmp.rename(learning_dir / "index.json")


def report_markdown(title: str, sections: list[tuple[str, list[dict]]]) -> str:
    lines = [f"# {title}", "", f"Generated: {now_utc()}", ""]
    for heading, rows in sections:
        lines.append(f"## {heading}")
        if not rows:
            lines.append("- None")
            lines.append("")
            continue
        for row in rows:
            source = row["source_paths"][0] if row.get("source_paths") else row.get("source_path", "")
            lines.append(
                f"- `{row['title']}` | category={row['category']} | confidence={row['confidence']:.2f} | "
                f"occurrences={row.get('occurrences', 1)} | promote={row.get('promote_target', '') or 'n/a'} | source={source}"
            )
            lines.append(f"  summary: {row['summary']}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_reports(root: Path, vectors: list[dict], bugs: list[dict], guardrails: list[dict], review_queue: list[dict]) -> None:
    report_dir = root / "memory" / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    fresh_vectors = [row for row in vectors if set(row.get("source_kinds", [])) - {"lesson", "training"}]
    fresh_bugs = [row for row in bugs if set(row.get("source_kinds", [])) - {"lesson", "training"}]
    fresh_guardrails = [row for row in guardrails if set(row.get("source_kinds", [])) - {"lesson", "training"}]
    fresh_queue = [row for row in review_queue if set(row.get("source_kinds", [])) - {"lesson", "training"}]
    (report_dir / "latest_learning_report.md").write_text(
        report_markdown(
            "Learning Dashboard",
            [
                ("New Vectors", fresh_vectors[:10]),
                ("Tooling Bugs And Stability Findings", fresh_bugs[:10]),
                ("Guardrails And Verification Rules", fresh_guardrails[:10]),
                ("Pending Promotions", fresh_queue[:10]),
            ],
        ),
        encoding="utf-8",
    )
    (report_dir / "latest_vector_report.md").write_text(
        report_markdown("Vector Report", [("Top Vectors", vectors[:20])]),
        encoding="utf-8",
    )
    (report_dir / "latest_tooling_bug_report.md").write_text(
        report_markdown("Tooling Bug Report", [("Tooling And Stability Findings", bugs[:20])]),
        encoding="utf-8",
    )


def _load_index(root: Path) -> dict | None:
    index_path = root / "memory" / "learning" / "index.json"
    if not index_path.exists():
        return None
    try:
        return json.loads(index_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def _query_index(index: dict, queries: list[str]) -> list[str]:
    """Return canonical IDs matching ALL query terms (AND logic).
    Query format: key:value where key is tag|port|service|cve|mode|phase|role."""
    result_sets: list[set[str]] = []
    bucket_map = {
        "tag": "by_tag",
        "port": "by_port",
        "service": "by_service",
        "svc": "by_service",
        "cve": "by_cve",
        "mode": "by_mode",
        "phase": "by_phase",
        "role": "by_role",
        "family": "by_opponent_family",
    }
    for q in queries:
        if ":" not in q:
            # Bare term: search across all buckets
            ids: set[str] = set()
            for bucket in bucket_map.values():
                ids |= set(index.get(bucket, {}).get(q, []))
            result_sets.append(ids)
        else:
            key, value = q.split(":", 1)
            bucket = bucket_map.get(key)
            if bucket:
                result_sets.append(set(index.get(bucket, {}).get(value, [])))
    if not result_sets:
        return []
    matched = result_sets[0]
    for s in result_sets[1:]:
        matched &= s
    return sorted(matched)


def cmd_lookup(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    index = _load_index(root)
    if index is None:
        print("[!] No index found. Run: learn_engine.py ingest --rebuild", file=sys.stderr)
        return 1
    queries = args.queries
    if not queries:
        # Show available keys
        print("[Index Keys]")
        print(f"  tags: {sorted(index.get('by_tag', {}).keys())}")
        print(f"  ports: {sorted(index.get('by_port', {}).keys(), key=lambda x: int(x) if x.isdigit() else 0)}")
        print(f"  services: {sorted(index.get('by_service', {}).keys())}")
        print(f"  cves: {sorted(index.get('by_cve', {}).keys())}")
        print(f"  modes: {sorted(index.get('by_mode', {}).keys())}")
        print(f"  phases: {sorted(index.get('by_phase', {}).keys())}")
        print(f"  roles: {sorted(index.get('by_role', {}).keys())}")
        print(f"  total entries: {index.get('meta', {}).get('entry_count', 0)}")
        return 0
    matched_ids = _query_index(index, queries)
    if not matched_ids:
        print("No matches.", file=sys.stderr)
        return 0
    entries = index.get("entries", {})
    fmt = getattr(args, "format", "brief")

    if fmt == "brief":
        for cid in matched_ids:
            e = entries.get(cid, {})
            parts = [f"[{e.get('category', '?')}]", e.get("title", cid)]
            if e.get("confidence"):
                parts.append(f"confidence={e['confidence']:.2f}")
            if e.get("ports"):
                parts.append(f"ports={','.join(e['ports'])}")
            if e.get("services"):
                parts.append(f"services={','.join(e['services'])}")
            if e.get("modes"):
                parts.append(f"modes={','.join(e['modes'])}")
            if e.get("phase"):
                parts.append(f"phase={e['phase']}")
            print(" | ".join(parts))
    elif fmt == "full":
        learning_dir = root / "memory" / "learning"
        all_entries = (
            jsonl_load(learning_dir / "vectors.jsonl")
            + jsonl_load(learning_dir / "bugs.jsonl")
            + jsonl_load(learning_dir / "guardrails.jsonl")
        )
        by_id = {e.get("canonical_id", ""): e for e in all_entries}
        for cid in matched_ids:
            full = by_id.get(cid)
            if full:
                print(json.dumps(full))
    elif fmt == "prompt":
        grouped: dict[str, list[dict]] = defaultdict(list)
        for cid in matched_ids:
            e = entries.get(cid, {})
            grouped[e.get("category", "other")].append(e)
        print("[Relevant Lessons]")
        for cat in ("playbook", "vector", "guardrail", "verification_rule", "bug"):
            items = grouped.get(cat, [])
            if not items:
                continue
            print(f"\n## {cat.replace('_', ' ').title()}s")
            for e in items:
                summary = e.get("summary_short", "") or e.get("title", "?")
                print(f"- {e.get('title', '?')}: {summary}" if cat == "playbook" else f"- {summary}")
                meta = []
                if e.get("ports"):
                    meta.append(f"ports={','.join(e['ports'])}")
                if e.get("services"):
                    meta.append(f"services={','.join(e['services'])}")
                if e.get("modes"):
                    meta.append(f"modes={','.join(e['modes'])}")
                if e.get("phase"):
                    meta.append(f"phase={e['phase']}")
                if meta:
                    print(f"  ({'; '.join(meta)})")
    return 0


def print_startup_digest(root: Path, tags: list[str] | None = None,
                         ports: list[str] | None = None,
                         services: list[str] | None = None,
                         modes: list[str] | None = None,
                         phases: list[str] | None = None,
                         roles: list[str] | None = None) -> int:
    index = _load_index(root)
    has_filters = bool(tags or ports or services or modes or phases or roles)

    if index and has_filters:
        # Targeted mode: show only relevant entries
        queries = []
        for t in (tags or []):
            queries.append(f"tag:{t}")
        for p in (ports or []):
            queries.append(f"port:{p}")
        for s in (services or []):
            queries.append(f"service:{s}")
        for m in (modes or []):
            queries.append(f"mode:{m}")
        for p in (phases or []):
            queries.append(f"phase:{p}")
        for r in (roles or []):
            queries.append(f"role:{r}")
        # Use OR logic for targeted mode (union of all filter matches)
        all_ids: set[str] = set()
        bucket_map = {
            "tag": "by_tag",
            "port": "by_port",
            "service": "by_service",
            "mode": "by_mode",
            "phase": "by_phase",
            "role": "by_role",
        }
        for q in queries:
            key, value = q.split(":", 1)
            bucket = bucket_map.get(key, "by_tag")
            all_ids |= set(index.get(bucket, {}).get(value, []))
        if not all_ids:
            print("[Learning Digest] No matching lessons for this target context.")
            return 0
        entries = index.get("entries", {})
        grouped: dict[str, list[dict]] = defaultdict(list)
        for cid in sorted(all_ids):
            e = entries.get(cid, {})
            grouped[e.get("category", "other")].append(e)
        desired_tags = set(tags or [])
        desired_ports = set(ports or [])
        desired_services = set(services or [])
        desired_modes = set(modes or [])
        desired_phases = set(phases or [])
        desired_roles = set(roles or [])

        def relevance(item: dict) -> tuple[int, float, str]:
            score = 0
            score += 4 * len(desired_tags & set(item.get("tags", [])))
            score += 4 * len(desired_services & set(item.get("services", [])))
            score += 3 * len(desired_ports & set(item.get("ports", [])))
            score += 2 * len(desired_modes & set(item.get("modes", [])))
            score += 2 if item.get("phase") in desired_phases else 0
            score += 2 * len(desired_roles & set(item.get("roles", [])))
            return (-score, -float(item.get("confidence", 0)), str(item.get("title", "")))

        print("[Learning Digest — Target Context]")
        for cat in ("playbook", "vector", "guardrail", "verification_rule", "bug"):
            items = grouped.get(cat, [])
            if not items:
                continue
            print(f"{cat.replace('_', ' ').title()}s:")
            for e in sorted(items, key=relevance)[:5]:
                summary = e.get("summary_short", "") or e.get("title", "?")
                print(f"- {e.get('title', '?')}: {summary}" if cat == "playbook" else f"- {summary}")
        # Opponent intel summary (when koth or opponent context)
        opp_families = index.get("by_opponent_family", {})
        if opp_families:
            opp_items = grouped.get("opponent_tool", [])
            print("Opponent Intel:")
            fam_counts = {fam: len(ids) for fam, ids in opp_families.items()}
            fam_str = ", ".join(f"{f} ({c})" for f, c in sorted(fam_counts.items(), key=lambda x: -x[1]))
            print(f"- Known families: {fam_str}")
            if opp_items:
                for e in sorted(opp_items, key=lambda x: -x.get("confidence", 0))[:3]:
                    summary = e.get("summary_short", "") or e.get("title", "?")
                    print(f"- {summary}")
        return 0

    # Generic mode: counts + lookup instructions
    learning_dir = root / "memory" / "learning"
    vectors = jsonl_load(learning_dir / "vectors.jsonl")
    bugs = jsonl_load(learning_dir / "bugs.jsonl")
    guardrails = jsonl_load(learning_dir / "guardrails.jsonl")
    review_queue = jsonl_load(learning_dir / "review_queue.jsonl")
    vectors = [row for row in vectors if set(row.get("source_kinds", [])) - {"lesson", "training"}]
    bugs = [row for row in bugs if set(row.get("source_kinds", [])) - {"lesson", "training"}]
    guardrails = [row for row in guardrails if set(row.get("source_kinds", [])) - {"lesson", "training"}]
    review_queue = [row for row in review_queue if set(row.get("source_kinds", [])) - {"lesson", "training"}]

    print("[Learning Index]")
    print(
        f"counts: vectors={len(vectors)} bugs={len(bugs)} "
        f"guardrails={len(guardrails)} pending_promotions={len(review_queue)}"
    )
    if index:
        idx_ports = sorted(index.get("by_port", {}).keys(), key=lambda x: int(x) if x.isdigit() else 0)
        idx_services = sorted(index.get("by_service", {}).keys())
        idx_tags = sorted(index.get("by_tag", {}).keys())
        idx_modes = sorted(index.get("by_mode", {}).keys())
        idx_phases = sorted(index.get("by_phase", {}).keys())
        print(f"index_keys: ports={idx_ports} services={idx_services} tags={idx_tags} modes={idx_modes} phases={idx_phases}")
    print()
    print("To load relevant lessons after choosing a target, run:")
    print("  python3 scripts/learn_engine.py --root ${CTF_ROOT:-.} lookup tag:web port:80 --format prompt")
    print("  python3 scripts/learn_engine.py --root ${CTF_ROOT:-.} lookup service:wordpress --format prompt")
    print("  python3 scripts/learn_engine.py --root ${CTF_ROOT:-.} lookup mode:pentest tag:web --format prompt")
    print("Combine terms for AND logic. Use --format prompt for injection-ready text.")
    return 0


# ─── LLM-backed pipeline functions ───────────────────────────────────────────

_CLASSIFY_PROMPT = """\
You are a CTF/pentest learning classifier. Refine each entry on stdin (JSONL).
Per entry output one JSON line with these fields:
{"event_id": "...", "category": "...", "title": "...", "confidence_delta": 0.0}

Valid categories: vector, guardrail, verification_rule, bug, false_lead, \
tooling_failure, stability_issue, opponent_tool, bug_bounty, skip
Rules:
- category: reclassify only if the regex assignment is clearly wrong
- title: concise (<80 char) action-oriented title. Format: "TECHNIQUE: what happened"
- confidence_delta: float between -0.2 and +0.2 to adjust existing confidence
- Set category to "skip" for noise/boilerplate entries
Output ONLY valid JSON lines, no other text."""

_DEDUP_PROMPT = """\
Identify semantic duplicates among these CTF learning entries (JSONL on stdin).
These entries have different text but may describe the same technique or rule.
Output JSON lines: {"merge": "sig_A", "into": "sig_B", "reason": "..."}
Only flag clear duplicates (same technique/finding), not merely related entries.
Output ONLY valid JSON lines, no other text. If no duplicates found, output nothing."""

_PROMOTE_PROMPT = """\
Write dense pentest methodology snippets for a PENTEST.md reference document.
Per entry on stdin (JSONL), output one JSON line:
{"canonical_id": "...", "draft_text": "### Title\\n- When: precondition\\n- Do: exact actions with commands\\n- Verify: how to confirm success\\n- Pitfall: common mistakes"}
Rules:
- Be specific and operational, not theoretical
- Include exact command examples where relevant
- Keep each draft under 8 lines
- Preserve technical accuracy from the summary field
Output ONLY valid JSON lines, no other text."""

_CONSOLIDATE_PROMPT = """\
Review these CTF learning entries (JSONL on stdin) and identify cleanup actions.
Output JSON lines with one of these formats:
{"action": "merge", "ids": ["id1", "id2"], "reason": "..."}
{"action": "demote", "id": "id1", "reason": "..."}
Rules:
- merge: entries that describe the same technique/finding despite different wording
- demote: low-value entries (generic, low confidence, single occurrence, no actionable content)
Only flag clear wins. Output ONLY valid JSON lines, no other text."""


def llm_refine_events(events: list[dict], no_llm: bool = False) -> list[dict]:
    """LLM-refine event classification. Falls back to returning events unchanged."""
    if no_llm or not events:
        return events
    batch_size = LLM_BATCH_SIZE["classify"]
    refined_map: dict[str, dict] = {}

    for i in range(0, len(events), batch_size):
        batch = events[i:i + batch_size]
        compact_batch = [
            {k: row[k] for k in ("event_id", "category", "title", "summary", "heading",
                                   "source_kind", "confidence") if k in row}
            for row in batch
        ]
        stdin_text = "\n".join(json.dumps(e) for e in compact_batch)
        result = llm_call("classify", _CLASSIFY_PROMPT, stdin_text, timeout_seconds=90)
        if result:
            for parsed in _parse_llm_jsonl(result):
                eid = parsed.get("event_id")
                if eid:
                    refined_map[eid] = parsed

    if not refined_map:
        return events

    out = []
    skipped = 0
    for event in events:
        ref = refined_map.get(event.get("event_id"))
        if not ref:
            out.append(event)
            continue
        if ref.get("category") == "skip":
            skipped += 1
            continue
        if ref.get("category"):
            event["category"] = ref["category"]
        if ref.get("title"):
            event["title"] = ref["title"]
        delta = ref.get("confidence_delta", 0)
        if isinstance(delta, (int, float)):
            event["confidence"] = max(0.25, min(0.99, round(event.get("confidence", 0.5) + delta, 2)))
        # Recompute derived fields after reclassification
        event["impact"] = impact_for(event["category"])
        event["promote_target"] = pick_promote_target(
            event["category"], event.get("tags", []), event["confidence"],
            event.get("occurrences", 1))
        out.append(event)

    if skipped:
        print(f"[+] LLM classification: refined {len(refined_map)} events, skipped {skipped} as noise")
    else:
        print(f"[+] LLM classification: refined {len(refined_map)} events")
    return out


def llm_find_dupes(grouped: dict[str, list[dict]], no_llm: bool = False) -> list[tuple[str, str]]:
    """Ask LLM to find semantic duplicates among singleton entries."""
    if no_llm:
        return []
    singletons = [(sig, group[0]) for sig, group in grouped.items() if len(group) == 1]
    if len(singletons) < 10:
        return []

    batch_size = LLM_BATCH_SIZE["dedup"]
    all_merges: list[tuple[str, str]] = []

    for i in range(0, len(singletons), batch_size):
        batch = singletons[i:i + batch_size]
        compact = [
            {"sig": sig[:32], "category": e.get("category", ""),
             "title": e.get("title", "")[:80], "summary": e.get("summary", "")[:100]}
            for sig, e in batch
        ]
        stdin_text = "\n".join(json.dumps(c) for c in compact)
        result = llm_call("dedup", _DEDUP_PROMPT, stdin_text, timeout_seconds=90)
        if result:
            sig_lookup = {sig[:32]: sig for sig, _ in batch}
            for parsed in _parse_llm_jsonl(result):
                merge_sig = sig_lookup.get(parsed.get("merge", ""))
                into_sig = sig_lookup.get(parsed.get("into", ""))
                if merge_sig and into_sig and merge_sig != into_sig:
                    all_merges.append((merge_sig, into_sig))

    if all_merges:
        print(f"[+] LLM dedup: found {len(all_merges)} semantic duplicate pair(s)")
    return all_merges


def llm_draft_promotions(entries: list[dict], no_llm: bool = False) -> dict[str, str]:
    """Generate LLM-backed promotion drafts. Returns {canonical_id: draft_text}."""
    if no_llm or not entries:
        return {}
    batch_size = LLM_BATCH_SIZE["promote"]
    drafts: dict[str, str] = {}

    for i in range(0, len(entries), batch_size):
        batch = entries[i:i + batch_size]
        compact = [
            {k: row.get(k, "") for k in ("canonical_id", "title", "summary", "category",
                                           "tags", "preconditions", "action_pattern",
                                           "verification_signal")}
            for row in batch
        ]
        stdin_text = "\n".join(json.dumps(c) for c in compact)
        result = llm_call("promote", _PROMOTE_PROMPT, stdin_text, timeout_seconds=120)
        if result:
            for parsed in _parse_llm_jsonl(result):
                cid = parsed.get("canonical_id")
                dt = parsed.get("draft_text")
                if cid and dt:
                    drafts[cid] = dt

    if drafts:
        print(f"[+] LLM promotion: generated {len(drafts)} draft(s)")
    return drafts


def llm_consolidate(vectors: list[dict], guardrails: list[dict], bugs: list[dict],
                    root: Path, no_llm: bool = False) -> None:
    """LLM-review canonical entries for merge/demote recommendations."""
    if no_llm:
        return
    all_entries = []
    for label, rows in [("vectors", vectors), ("guardrails", guardrails), ("bugs", bugs)]:
        for row in rows[:50]:  # cap per category to control tokens
            all_entries.append({
                "section": label,
                "id": row.get("canonical_id", "?"),
                "title": row.get("title", "?")[:80],
                "conf": row.get("confidence", 0),
                "occ": row.get("occurrences", 1),
                "promote": row.get("promote_target", ""),
            })
    if len(all_entries) < 10:
        return

    stdin_text = "\n".join(json.dumps(e) for e in all_entries)
    result = llm_call("consolidate", _CONSOLIDATE_PROMPT, stdin_text, timeout_seconds=120)
    if not result:
        return

    recommendations = _parse_llm_jsonl(result)
    if not recommendations:
        return

    report_dir = root / "memory" / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    report_lines = [
        "# Learning Consolidation Review",
        "",
        f"Generated: {now_utc()} (model: {LLM_MODELS['consolidate']})",
        f"Entries analyzed: {len(all_entries)}",
        "",
    ]
    for rec in recommendations:
        action = rec.get("action", "?")
        if action == "merge":
            ids = rec.get("ids", [])
            report_lines.append(f"- MERGE {' + '.join(ids)}: {rec.get('reason', '')}")
        elif action == "demote":
            report_lines.append(f"- DEMOTE {rec.get('id', '?')}: {rec.get('reason', '')}")

    (report_dir / "compact_review.md").write_text("\n".join(report_lines) + "\n", encoding="utf-8")
    print(f"[+] LLM consolidation: {len(recommendations)} recommendation(s) → memory/reports/compact_review.md")


def cmd_ingest(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    learning_dir = root / "memory" / "learning"
    learning_dir.mkdir(parents=True, exist_ok=True)
    events_file = learning_dir / "events.jsonl"

    if args.rebuild and events_file.exists():
        events_file.write_text("", encoding="utf-8")

    existing_events = jsonl_load(events_file)
    known_ids = {row["event_id"] for row in existing_events if "event_id" in row}

    new_rows: list[dict] = []
    for path in discover_paths(root, args.source_path):
        for event in extract_events(root, path):
            if event.event_id in known_ids:
                continue
            row = asdict(event)
            if args.session_id:
                row["session_id"] = args.session_id
            new_rows.append(row)
            known_ids.add(event.event_id)

    # LLM refinement pass on new events (cheap model, batched)
    if new_rows:
        new_rows = llm_refine_events(new_rows, no_llm=getattr(args, "no_llm", False))
        jsonl_append(events_file, new_rows)

    all_events = jsonl_load(events_file)
    vectors, bugs, guardrails, review_queue = canonicalize(
        all_events, no_llm=getattr(args, "no_llm", False))
    jsonl_write(learning_dir / "vectors.jsonl", vectors)
    jsonl_write(learning_dir / "bugs.jsonl", bugs)
    jsonl_write(learning_dir / "guardrails.jsonl", guardrails)
    jsonl_write(learning_dir / "review_queue.jsonl", review_queue)
    build_index(learning_dir, vectors + bugs + guardrails)

    if args.generate_reports:
        render_reports(root, vectors, bugs, guardrails, review_queue)

    print(
        f"[+] Learning ingest complete: new_events={len(new_rows)} total_events={len(all_events)} "
        f"vectors={len(vectors)} bugs={len(bugs)} guardrails={len(guardrails)} "
        f"review_queue={len(review_queue)}"
    )
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    learning_dir = root / "memory" / "learning"
    vectors = jsonl_load(learning_dir / "vectors.jsonl")
    bugs = jsonl_load(learning_dir / "bugs.jsonl")
    guardrails = jsonl_load(learning_dir / "guardrails.jsonl")
    review_queue = jsonl_load(learning_dir / "review_queue.jsonl")
    render_reports(root, vectors, bugs, guardrails, review_queue)
    print("[+] Learning reports refreshed.")
    return 0


def cmd_promote(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    learning_dir = root / "memory" / "learning"
    review_queue = jsonl_load(learning_dir / "review_queue.jsonl")
    selected = [row for row in review_queue if row.get("status", "candidate") == args.status]
    selected = sorted(selected, key=lambda item: (-item["confidence"], -item["occurrences"], item["title"]))
    if args.limit:
        selected = selected[: args.limit]

    groups: dict[str, list[dict]] = defaultdict(list)
    for row in selected:
        groups[row.get("promote_target") or "unassigned"].append(row)

    # LLM-generate promotion drafts for quality-critical targets
    no_llm = getattr(args, "no_llm", False)
    llm_targets = {"PENTEST.md", "koth_playbook.md"}
    llm_entries = [r for r in selected if r.get("promote_target") in llm_targets]
    llm_drafts = llm_draft_promotions(llm_entries, no_llm=no_llm)

    lines = ["# Promotion Drafts", "", f"Generated: {now_utc()}", ""]
    for target in sorted(groups):
        lines.append(f"## {target}")
        for row in groups[target]:
            lines.append(f"### {row['title']}")
            lines.append(f"- Confidence: {row['confidence']:.2f}")
            lines.append(f"- Occurrences: {row['occurrences']}")
            lines.append(f"- Sources: {', '.join(row.get('source_paths', [])[:3])}")
            lines.append("")
            # Use LLM draft if available, otherwise regenerate from template
            cid = row.get("canonical_id", "")
            dt = llm_drafts.get(cid) or row.get("draft_text") or draft_for(
                row["title"], row.get("summary", row["title"]),
                row["category"], row.get("promote_target", ""),
                row.get("verification_signal", ""),
            )
            lines.append(dt)
            lines.append("")

    report_dir = root / "memory" / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    output = report_dir / "promotion_drafts.md"
    output.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    print(f"[+] Promotion drafts written: {output}")
    return 0


def cmd_opponent_ingest(args: argparse.Namespace) -> int:
    """Quick ingest of a single opponent tool report for real-time mid-session use."""
    root = Path(args.root).resolve()
    report_path = Path(args.report_path).resolve()
    if not report_path.exists():
        print(f"[!] Report not found: {report_path}", file=sys.stderr)
        return 1

    learning_dir = root / "memory" / "learning"
    learning_dir.mkdir(parents=True, exist_ok=True)
    events_file = learning_dir / "events.jsonl"
    known_ids = {row["event_id"] for row in jsonl_load(events_file)}

    # Extract events from opponent tool report
    events = extract_events(root, report_path)
    if not events:
        print("[!] No events extracted from report.", file=sys.stderr)
        return 1

    new_rows = []
    for event in events:
        if event.event_id not in known_ids:
            row = asdict(event)
            if args.session_id:
                row["session_id"] = args.session_id
            new_rows.append(row)
            known_ids.add(event.event_id)

    if not new_rows:
        print("[*] No new events (all already known).")
        return 0

    # Skip LLM refinement for speed — opponent tools are pre-classified
    jsonl_append(events_file, new_rows)

    # Incremental re-canonicalize
    all_events = jsonl_load(events_file)
    vectors, bugs, guardrails, review_queue = canonicalize(all_events, no_llm=True)
    jsonl_write(learning_dir / "vectors.jsonl", vectors)
    jsonl_write(learning_dir / "bugs.jsonl", bugs)
    jsonl_write(learning_dir / "guardrails.jsonl", guardrails)
    jsonl_write(learning_dir / "review_queue.jsonl", review_queue)
    build_index(learning_dir, vectors + bugs + guardrails)

    # Summarize
    opp_events = [r for r in new_rows if r.get("source_kind") == "opponent_tool" or r.get("category") == "opponent_tool"]
    families = set()
    for r in opp_events:
        fam = _extract_opponent_family(r)
        if fam:
            families.add(fam)

    print(
        f"[+] Opponent tool ingested: {len(new_rows)} events from {report_path.name}"
        + (f" families=[{','.join(sorted(families))}]" if families else "")
    )
    return 0


def cmd_compact(args: argparse.Namespace) -> int:
    """One-time compaction: re-canonicalize all events with compact field stripping."""
    root = Path(args.root).resolve()
    learning_dir = root / "memory" / "learning"
    events_file = learning_dir / "events.jsonl"

    if not events_file.exists():
        print("[!] No events.jsonl found.")
        return 1

    # Archive old events if requested
    if args.archive_days and args.archive_days > 0:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=args.archive_days)).isoformat()
        all_events = jsonl_load(events_file)
        recent = [e for e in all_events if e.get("ts", "") >= cutoff]
        archived = [e for e in all_events if e.get("ts", "") < cutoff]
        if archived:
            archive_file = learning_dir / "events.archive.jsonl"
            jsonl_append(archive_file, archived)
            jsonl_write(events_file, recent)
            print(f"[+] Archived {len(archived)} events older than {args.archive_days} days")
            print(f"    Active events: {len(recent)}, Archive: {archive_file}")
        else:
            print(f"[*] No events older than {args.archive_days} days to archive.")
            recent = all_events
    else:
        recent = jsonl_load(events_file)

    # Backup originals
    for fname in ["vectors.jsonl", "bugs.jsonl", "guardrails.jsonl", "review_queue.jsonl"]:
        src = learning_dir / fname
        if src.exists():
            bak = learning_dir / f"{fname}.bak"
            shutil.copy2(src, bak)

    # Pre-compaction sizes
    pre_sizes = {}
    for fname in ["vectors.jsonl", "bugs.jsonl", "guardrails.jsonl", "review_queue.jsonl"]:
        src = learning_dir / fname
        if src.exists():
            pre_sizes[fname] = src.stat().st_size

    # Re-canonicalize with compaction
    no_llm = getattr(args, "no_llm", False)
    vectors, bugs, guardrails, review_queue = canonicalize(recent, no_llm=no_llm)

    # LLM consolidation review (merge/demote recommendations)
    llm_consolidate(vectors, guardrails, bugs, root, no_llm=no_llm)

    jsonl_write(learning_dir / "vectors.jsonl", vectors)
    jsonl_write(learning_dir / "bugs.jsonl", bugs)
    jsonl_write(learning_dir / "guardrails.jsonl", guardrails)
    jsonl_write(learning_dir / "review_queue.jsonl", review_queue)
    build_index(learning_dir, vectors + bugs + guardrails)

    # Report savings
    print("[+] Compaction complete:")
    for fname in ["vectors.jsonl", "bugs.jsonl", "guardrails.jsonl", "review_queue.jsonl"]:
        src = learning_dir / fname
        post = src.stat().st_size if src.exists() else 0
        pre = pre_sizes.get(fname, 0)
        if pre > 0:
            pct = round((1 - post / pre) * 100)
            print(f"    {fname}: {pre:,} -> {post:,} bytes ({pct}% reduction)")
        else:
            print(f"    {fname}: {post:,} bytes (new)")

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Structured learning engine for this CTF workspace")
    parser.add_argument("--root", default=str(Path.cwd()))
    parser.add_argument("--no-llm", action="store_true", default=False,
                        help="Disable LLM-backed processing, use regex/mechanical only")
    sub = parser.add_subparsers(dest="command", required=True)

    ingest = sub.add_parser("ingest")
    ingest.add_argument("--session-id", default="")
    ingest.add_argument("--source-path", action="append", default=[])
    ingest.add_argument("--generate-reports", action="store_true", default=False)
    ingest.add_argument("--rebuild", action="store_true", default=False)
    ingest.set_defaults(func=cmd_ingest)

    report = sub.add_parser("report")
    report.set_defaults(func=cmd_report)

    promote = sub.add_parser("promote")
    promote.add_argument("--status", default="candidate")
    promote.add_argument("--limit", type=int, default=25)
    promote.set_defaults(func=cmd_promote)

    compact = sub.add_parser("compact")
    compact.add_argument("--archive-days", type=int, default=0,
                         help="Archive events older than N days (0=no archive)")
    compact.set_defaults(func=cmd_compact)

    digest = sub.add_parser("startup-digest")
    digest.add_argument("--tags", nargs="*", default=None)
    digest.add_argument("--ports", nargs="*", default=None)
    digest.add_argument("--services", nargs="*", default=None)
    digest.add_argument("--modes", nargs="*", default=None)
    digest.add_argument("--phases", nargs="*", default=None)
    digest.add_argument("--roles", nargs="*", default=None)
    digest.set_defaults(func=lambda args: print_startup_digest(
        Path(args.root).resolve(),
        tags=args.tags,
        ports=args.ports,
        services=args.services,
        modes=args.modes,
        phases=args.phases,
        roles=args.roles,
    ))

    lookup = sub.add_parser("lookup")
    lookup.add_argument("queries", nargs="*", help="Query terms: tag:X port:X service:X cve:X mode:X phase:X role:X family:X")
    lookup.add_argument("--format", choices=["brief", "full", "prompt"], default="brief")
    lookup.set_defaults(func=cmd_lookup)

    context = sub.add_parser("context")
    context.add_argument("queries", nargs="*", help="Alias for lookup --format prompt")
    context.set_defaults(func=lambda args: cmd_lookup(argparse.Namespace(queries=args.queries, format="prompt", root=args.root)))

    opp_ingest = sub.add_parser("opponent-ingest")
    opp_ingest.add_argument("report_path", help="Path to opponent tool report markdown")
    opp_ingest.add_argument("--session-id", default="")
    opp_ingest.set_defaults(func=cmd_opponent_ingest)

    return parser


def main(argv: list[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
