#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

TERMINAL_RUN_STATES = {"completed", "failed", "blocked", "cancelled"}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _safe_ts(value: str) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _slug(value: str) -> str:
    lowered = "".join(ch.lower() if ch.isalnum() else "-" for ch in value)
    while "--" in lowered:
        lowered = lowered.replace("--", "-")
    return lowered.strip("-") or "case"


def _load_manifest(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _text_corpus(payload: dict[str, Any]) -> str:
    findings = payload.get("findings") or []
    vectors = payload.get("vectors") or []
    facts = payload.get("facts") or []
    chunks: list[str] = []
    for row in findings:
        chunks.append(str(row.get("title") or ""))
        chunks.append(str(row.get("summary") or ""))
        chunks.append(str(row.get("evidence") or ""))
    for row in vectors:
        chunks.append(str(row.get("title") or ""))
        chunks.append(str(row.get("summary") or ""))
        chunks.append(str(row.get("evidence") or ""))
    for row in facts:
        chunks.append(str(row.get("kind") or ""))
        chunks.append(str(row.get("value") or ""))
    return " ".join(chunks).lower()


def _normalize_ground_truth(record: dict[str, Any]) -> dict[str, Any]:
    needles: list[str] = []
    if isinstance(record.get("needles"), list):
        needles = [str(item).strip().lower() for item in record["needles"] if str(item).strip()]
    elif record.get("needle"):
        needles = [str(record["needle"]).strip().lower()]
    return {
        "id": str(record.get("id") or record.get("class") or "gt"),
        "class": str(record.get("class") or ""),
        "severity": str(record.get("severity") or ""),
        "needles": needles,
    }


def _evaluate_ground_truth(ground_truth: list[dict[str, Any]], corpus: str) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    matched = 0
    for item in ground_truth:
        norm = _normalize_ground_truth(item)
        needles = norm["needles"]
        if not needles:
            checks.append({**norm, "matched": False, "reason": "no-needles"})
            continue
        found = [needle for needle in needles if needle in corpus]
        ok = len(found) > 0
        if ok:
            matched += 1
        checks.append({**norm, "matched": ok, "matched_needles": found})
    return {"total": len(checks), "matched": matched, "checks": checks}


@dataclass(slots=True)
class RunOutcome:
    run_id: str
    status: str
    elapsed_seconds: float
    started_at: str
    updated_at: str
    vectors: int
    findings: int
    browser_pages: int
    browser_routes: int
    approvals_total: int
    approvals_pending: int
    report_path: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "status": self.status,
            "elapsed_seconds": round(self.elapsed_seconds, 3),
            "started_at": self.started_at,
            "updated_at": self.updated_at,
            "vectors": self.vectors,
            "findings": self.findings,
            "browser_pages": self.browser_pages,
            "browser_routes": self.browser_routes,
            "approvals_total": self.approvals_total,
            "approvals_pending": self.approvals_pending,
            "report_path": self.report_path,
        }


class VantixClient:
    def __init__(self, api_base: str, *, username: str = "", password: str = "", timeout: float = 60.0) -> None:
        self.api_base = api_base.rstrip("/")
        self.client = httpx.Client(base_url=self.api_base, timeout=timeout, follow_redirects=True)
        self.csrf = ""
        if username and password:
            self.login(username=username, password=password)

    def close(self) -> None:
        self.client.close()

    def _headers(self) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self.csrf:
            headers["X-CSRF-Token"] = self.csrf
        return headers

    def login(self, *, username: str, password: str) -> None:
        response = self.client.post("/api/v1/auth/login", json={"username": username, "password": password})
        response.raise_for_status()
        payload = response.json()
        self.csrf = str(payload.get("csrf") or "")

    def chat_start(self, *, message: str, mode: str, target: str, source_input: dict[str, Any] | None = None) -> dict[str, Any]:
        metadata: dict[str, Any] = {"start_new_run": True}
        if source_input:
            metadata["source_input"] = source_input
        response = self.client.post(
            "/api/v1/chat",
            headers=self._headers(),
            json={"message": message, "mode": mode, "target": target, "metadata": metadata},
        )
        response.raise_for_status()
        return response.json()

    def get_run(self, run_id: str) -> dict[str, Any]:
        response = self.client.get(f"/api/v1/runs/{run_id}", headers=self._headers())
        response.raise_for_status()
        return response.json()

    def get_graph(self, run_id: str) -> dict[str, Any]:
        response = self.client.get(f"/api/v1/runs/{run_id}/graph", headers=self._headers())
        response.raise_for_status()
        return response.json()

    def get_results(self, run_id: str) -> dict[str, Any]:
        response = self.client.get(f"/api/v1/runs/{run_id}/results", headers=self._headers())
        response.raise_for_status()
        return response.json()

    def get_vectors(self, run_id: str) -> list[dict[str, Any]]:
        response = self.client.get(f"/api/v1/runs/{run_id}/vectors", headers=self._headers())
        response.raise_for_status()
        return list(response.json())

    def get_facts(self, run_id: str) -> list[dict[str, Any]]:
        response = self.client.get(f"/api/v1/runs/{run_id}/facts", headers=self._headers())
        response.raise_for_status()
        return list(response.json())

    def get_browser_state(self, run_id: str) -> dict[str, Any]:
        response = self.client.get(f"/api/v1/runs/{run_id}/browser-state", headers=self._headers())
        response.raise_for_status()
        return response.json()


def _wait_for_terminal_state(client: VantixClient, run_id: str, *, timeout_seconds: int, poll_seconds: float) -> dict[str, Any]:
    started = time.monotonic()
    while True:
        run = client.get_run(run_id)
        if str(run.get("status") or "").lower() in TERMINAL_RUN_STATES:
            return run
        if time.monotonic() - started >= timeout_seconds:
            return run
        time.sleep(max(0.2, poll_seconds))


def _execute_variant(
    *,
    client: VantixClient,
    case: dict[str, Any],
    variant: str,
    mode: str,
    timeout_seconds: int,
    poll_seconds: float,
) -> dict[str, Any]:
    variant_cfg = dict(case.get(variant) or {})
    source_input = variant_cfg.get("source_input")
    objective = str(variant_cfg.get("objective") or case.get("objective") or f"Full pentest of {case['target']}")
    target = str(case["target"])

    wall_start = _utc_now()
    perf_start = time.monotonic()
    chat_payload = client.chat_start(message=objective, mode=mode, target=target, source_input=source_input)
    run_id = str(chat_payload["run"]["id"])
    terminal_run = _wait_for_terminal_state(client, run_id, timeout_seconds=timeout_seconds, poll_seconds=poll_seconds)
    elapsed = time.monotonic() - perf_start
    wall_end = _utc_now()

    graph = client.get_graph(run_id)
    results = client.get_results(run_id)
    vectors = client.get_vectors(run_id)
    facts = client.get_facts(run_id)
    browser = client.get_browser_state(run_id)

    approvals = list(graph.get("approvals") or [])
    approvals_pending = [item for item in approvals if str(item.get("status") or "") == "pending"]
    findings = list(results.get("findings") or [])
    report_path = str(results.get("report_path") or "")

    outcome = RunOutcome(
        run_id=run_id,
        status=str(terminal_run.get("status") or ""),
        elapsed_seconds=elapsed,
        started_at=wall_start.isoformat(),
        updated_at=wall_end.isoformat(),
        vectors=len(vectors),
        findings=len(findings),
        browser_pages=int(browser.get("pages_visited") or 0),
        browser_routes=int(browser.get("routes_discovered") or 0),
        approvals_total=len(approvals),
        approvals_pending=len(approvals_pending),
        report_path=report_path,
    )

    thresholds = dict(case.get("success_thresholds") or {})
    min_vectors = int(thresholds.get(f"min_vectors_{variant}", thresholds.get("min_vectors", 0)) or 0)
    min_findings = int(thresholds.get(f"min_findings_{variant}", thresholds.get("min_findings", 0)) or 0)
    min_browser_routes = int(thresholds.get(f"min_browser_routes_{variant}", thresholds.get("min_browser_routes", 0)) or 0)
    gt = _evaluate_ground_truth(list(case.get("ground_truth") or []), _text_corpus({"findings": findings, "vectors": vectors, "facts": facts}))
    success = (
        outcome.status == "completed"
        and outcome.vectors >= min_vectors
        and outcome.findings >= min_findings
        and outcome.browser_routes >= min_browser_routes
        and (gt["matched"] == gt["total"] if gt["total"] > 0 else True)
    )

    return {
        "variant": variant,
        "objective": objective,
        "target": target,
        "source_input": source_input or {"type": "none"},
        "chat_response": chat_payload,
        "run": outcome.as_dict(),
        "thresholds": {
            "min_vectors": min_vectors,
            "min_findings": min_findings,
            "min_browser_routes": min_browser_routes,
        },
        "ground_truth_eval": gt,
        "success": success,
        "artifacts": {
            "report_path": report_path,
            "report_json_path": str(results.get("report_json_path") or ""),
            "comprehensive_report_path": str(results.get("comprehensive_report_path") or ""),
            "comprehensive_report_json_path": str(results.get("comprehensive_report_json_path") or ""),
            "artifact_index_path": str(results.get("artifact_index_path") or ""),
            "timeline_csv_path": str(results.get("timeline_csv_path") or ""),
        },
        "counts": {
            "vectors": len(vectors),
            "findings": len(findings),
            "facts": len(facts),
        },
    }


def _summary_markdown(payload: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append(f"# XBOW Evaluation Summary ({payload['run_id']})")
    lines.append("")
    lines.append(f"- Generated at: {payload['generated_at']}")
    lines.append(f"- Manifest: {payload['manifest_path']}")
    lines.append(f"- API base: {payload['api_base']}")
    lines.append(f"- Cases: {len(payload['cases'])}")
    lines.append("")
    lines.append("| case_id | variant | run_id | status | elapsed_s | vectors | findings | browser_routes | gt_matched | success |")
    lines.append("|---|---|---|---|---:|---:|---:|---:|---:|---|")
    for case in payload["cases"]:
        case_id = case["case_id"]
        for variant in ("black_box", "white_box"):
            if variant not in case:
                continue
            row = case[variant]
            run = row["run"]
            gt = row["ground_truth_eval"]
            lines.append(
                f"| {case_id} | {variant} | {run['run_id']} | {run['status']} | {run['elapsed_seconds']:.1f} | "
                f"{run['vectors']} | {run['findings']} | {run['browser_routes']} | {gt['matched']}/{gt['total']} | {row['success']} |"
            )
        if "black_box" in case and "white_box" in case:
            bb = case["black_box"]["run"]
            wb = case["white_box"]["run"]
            lines.append(
                f"| {case_id} | delta (wb-bb) | - | - | {wb['elapsed_seconds']-bb['elapsed_seconds']:.1f} | "
                f"{wb['vectors']-bb['vectors']} | {wb['findings']-bb['findings']} | {wb['browser_routes']-bb['browser_routes']} | - | - |"
            )
    return "\n".join(lines) + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run timed XBOW black-box/white-box evaluation against Vantix.")
    parser.add_argument("--manifest", required=True, help="Path to xbow benchmark manifest JSON.")
    parser.add_argument("--api-base", default=os.getenv("VANTIX_API_BASE", "http://127.0.0.1:8787"))
    parser.add_argument("--username", default=os.getenv("VANTIX_USERNAME", ""))
    parser.add_argument("--password", default=os.getenv("VANTIX_PASSWORD", ""))
    parser.add_argument("--mode", default="pentest")
    parser.add_argument("--timeout-seconds", type=int, default=1800)
    parser.add_argument("--poll-seconds", type=float, default=2.0)
    parser.add_argument("--case-id", default="", help="Run one case_id only.")
    parser.add_argument("--skip-white-box", action="store_true", default=False)
    parser.add_argument("--skip-black-box", action="store_true", default=False)
    parser.add_argument("--output-dir", default="", help="Directory for result JSON/MD.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    manifest_path = Path(args.manifest).expanduser().resolve()
    manifest = _load_manifest(manifest_path)

    default_root = Path(os.getenv("SECOPS_RUNTIME_ROOT", "~/.local/state/ctf-security-ops/vantix-local")).expanduser()
    stamp = _utc_now().strftime("%Y%m%dT%H%M%SZ")
    run_id = f"xbow-eval-{stamp.lower()}"
    output_dir = Path(args.output_dir).expanduser() if args.output_dir else default_root / "reports" / "xbow-eval" / run_id
    output_dir.mkdir(parents=True, exist_ok=True)

    client = VantixClient(api_base=args.api_base, username=args.username, password=args.password)
    cases_out: list[dict[str, Any]] = []
    try:
        cases = list(manifest.get("cases") or [])
        if args.case_id:
            cases = [row for row in cases if str(row.get("case_id") or "") == args.case_id]
        for case in cases:
            case_id = str(case.get("case_id") or "")
            if not case_id:
                continue
            out_case: dict[str, Any] = {"case_id": case_id, "target": str(case.get("target") or "")}
            if not args.skip_black_box:
                out_case["black_box"] = _execute_variant(
                    client=client,
                    case=case,
                    variant="black_box",
                    mode=args.mode,
                    timeout_seconds=args.timeout_seconds,
                    poll_seconds=args.poll_seconds,
                )
            if not args.skip_white_box and case.get("white_box"):
                out_case["white_box"] = _execute_variant(
                    client=client,
                    case=case,
                    variant="white_box",
                    mode=args.mode,
                    timeout_seconds=args.timeout_seconds,
                    poll_seconds=args.poll_seconds,
                )
            case_path = output_dir / f"{_slug(case_id)}.json"
            case_path.write_text(json.dumps(out_case, indent=2), encoding="utf-8")
            cases_out.append(out_case)
    finally:
        client.close()

    summary = {
        "run_id": run_id,
        "generated_at": _utc_now().isoformat(),
        "manifest_path": str(manifest_path),
        "api_base": args.api_base,
        "cases": cases_out,
    }
    summary_path = output_dir / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    md_path = output_dir / "summary.md"
    md_path.write_text(_summary_markdown(summary), encoding="utf-8")
    print(json.dumps({"ok": True, "output_dir": str(output_dir), "summary_json": str(summary_path), "summary_md": str(md_path)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
