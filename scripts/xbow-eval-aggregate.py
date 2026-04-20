#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from dataclasses import dataclass
from pathlib import Path
from statistics import mean
from typing import Any


@dataclass(slots=True)
class VariantRow:
    suite: str
    case_id: str
    variant: str
    run_id: str
    status: str
    elapsed_seconds: float
    vectors: int
    findings: int
    browser_routes: int
    gt_total: int
    gt_matched: int
    success: bool
    report_path: str
    comprehensive_report_path: str
    timeline_csv_path: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "suite": self.suite,
            "case_id": self.case_id,
            "variant": self.variant,
            "run_id": self.run_id,
            "status": self.status,
            "elapsed_seconds": round(self.elapsed_seconds, 3),
            "vectors": self.vectors,
            "findings": self.findings,
            "browser_routes": self.browser_routes,
            "gt_total": self.gt_total,
            "gt_matched": self.gt_matched,
            "success": self.success,
            "report_path": self.report_path,
            "comprehensive_report_path": self.comprehensive_report_path,
            "timeline_csv_path": self.timeline_csv_path,
        }


def _load_summary(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _suite_name(path: Path) -> str:
    parent = path.parent
    return parent.name or str(parent)


def _extract_rows(summary_path: Path) -> list[VariantRow]:
    payload = _load_summary(summary_path)
    suite = _suite_name(summary_path)
    rows: list[VariantRow] = []
    for case in payload.get("cases") or []:
        case_id = str(case.get("case_id") or "")
        if not case_id:
            continue
        for variant in ("black_box", "white_box"):
            record = case.get(variant)
            if not isinstance(record, dict):
                continue
            run = dict(record.get("run") or {})
            gt = dict(record.get("ground_truth_eval") or {})
            rows.append(
                VariantRow(
                    suite=suite,
                    case_id=case_id,
                    variant=variant,
                    run_id=str(run.get("run_id") or ""),
                    status=str(run.get("status") or ""),
                    elapsed_seconds=float(run.get("elapsed_seconds") or 0.0),
                    vectors=int(run.get("vectors") or 0),
                    findings=int(run.get("findings") or 0),
                    browser_routes=int(run.get("browser_routes") or 0),
                    gt_total=int(gt.get("total") or 0),
                    gt_matched=int(gt.get("matched") or 0),
                    success=bool(record.get("success")),
                    report_path=str(record.get("artifacts", {}).get("report_path") or ""),
                    comprehensive_report_path=str(record.get("artifacts", {}).get("comprehensive_report_path") or ""),
                    timeline_csv_path=str(record.get("artifacts", {}).get("timeline_csv_path") or ""),
                )
            )
    return rows


def _variant_metrics(rows: list[VariantRow], variant: str) -> dict[str, Any]:
    scoped = [row for row in rows if row.variant == variant]
    if not scoped:
        return {
            "count": 0,
            "success_rate": 0.0,
            "avg_elapsed_seconds": 0.0,
            "avg_vectors": 0.0,
            "avg_findings": 0.0,
            "avg_browser_routes": 0.0,
            "avg_ground_truth_coverage": 0.0,
        }
    success_rate = sum(1 for row in scoped if row.success) / len(scoped)
    gt_cov = [
        (row.gt_matched / row.gt_total) if row.gt_total > 0 else 1.0
        for row in scoped
    ]
    return {
        "count": len(scoped),
        "success_rate": round(success_rate, 4),
        "avg_elapsed_seconds": round(mean(row.elapsed_seconds for row in scoped), 3),
        "avg_vectors": round(mean(row.vectors for row in scoped), 3),
        "avg_findings": round(mean(row.findings for row in scoped), 3),
        "avg_browser_routes": round(mean(row.browser_routes for row in scoped), 3),
        "avg_ground_truth_coverage": round(mean(gt_cov), 4),
    }


def _deltas(rows: list[VariantRow]) -> dict[str, Any]:
    by_case: dict[tuple[str, str], dict[str, VariantRow]] = {}
    for row in rows:
        key = (row.suite, row.case_id)
        by_case.setdefault(key, {})[row.variant] = row
    deltas: list[dict[str, Any]] = []
    for (suite, case_id), variants in sorted(by_case.items()):
        bb = variants.get("black_box")
        wb = variants.get("white_box")
        if not bb or not wb:
            continue
        deltas.append(
            {
                "suite": suite,
                "case_id": case_id,
                "elapsed_seconds_delta": round(wb.elapsed_seconds - bb.elapsed_seconds, 3),
                "vectors_delta": wb.vectors - bb.vectors,
                "findings_delta": wb.findings - bb.findings,
                "browser_routes_delta": wb.browser_routes - bb.browser_routes,
                "success_delta": int(wb.success) - int(bb.success),
            }
        )
    if not deltas:
        return {"count": 0, "rows": [], "averages": {}}
    return {
        "count": len(deltas),
        "rows": deltas,
        "averages": {
            "elapsed_seconds_delta": round(mean(row["elapsed_seconds_delta"] for row in deltas), 3),
            "vectors_delta": round(mean(row["vectors_delta"] for row in deltas), 3),
            "findings_delta": round(mean(row["findings_delta"] for row in deltas), 3),
            "browser_routes_delta": round(mean(row["browser_routes_delta"] for row in deltas), 3),
            "success_delta": round(mean(row["success_delta"] for row in deltas), 3),
        },
    }


def _render_markdown(report: dict[str, Any], rows: list[VariantRow]) -> str:
    lines: list[str] = []
    lines.append(f"# XBOW Evaluation Aggregate ({report['generated_at']})")
    lines.append("")
    lines.append(f"- Suites: {len(report['suite_sources'])}")
    lines.append(f"- Variant runs: {len(rows)}")
    lines.append("")
    lines.append("## Variant Metrics")
    lines.append("")
    lines.append("| variant | count | success_rate | avg_elapsed_s | avg_vectors | avg_findings | avg_browser_routes | avg_gt_coverage |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|")
    for variant in ("black_box", "white_box"):
        metric = report["metrics"].get(variant, {})
        lines.append(
            f"| {variant} | {metric.get('count',0)} | {metric.get('success_rate',0)} | {metric.get('avg_elapsed_seconds',0)} | "
            f"{metric.get('avg_vectors',0)} | {metric.get('avg_findings',0)} | {metric.get('avg_browser_routes',0)} | "
            f"{metric.get('avg_ground_truth_coverage',0)} |"
        )
    lines.append("")
    lines.append("## White-Box Delta (wb - bb)")
    lines.append("")
    deltas = report["deltas"]
    if deltas["count"] == 0:
        lines.append("No paired black/white-box cases found.")
    else:
        avg = deltas["averages"]
        lines.append(f"- Paired cases: {deltas['count']}")
        lines.append(f"- Avg elapsed delta (s): {avg['elapsed_seconds_delta']}")
        lines.append(f"- Avg vectors delta: {avg['vectors_delta']}")
        lines.append(f"- Avg findings delta: {avg['findings_delta']}")
        lines.append(f"- Avg browser routes delta: {avg['browser_routes_delta']}")
        lines.append(f"- Avg success delta: {avg['success_delta']}")
    lines.append("")
    lines.append("## Per-Run Rows")
    lines.append("")
    lines.append("| suite | case_id | variant | run_id | status | elapsed_s | vectors | findings | browser_routes | gt | success |")
    lines.append("|---|---|---|---|---|---:|---:|---:|---:|---:|---|")
    for row in rows:
        gt_ratio = f"{row.gt_matched}/{row.gt_total}"
        lines.append(
            f"| {row.suite} | {row.case_id} | {row.variant} | {row.run_id} | {row.status} | "
            f"{row.elapsed_seconds:.1f} | {row.vectors} | {row.findings} | {row.browser_routes} | {gt_ratio} | {row.success} |"
        )
    return "\n".join(lines) + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Aggregate outputs from one or more xbow-eval-run summary.json files.")
    parser.add_argument(
        "--input",
        action="append",
        required=True,
        help="Path to summary.json OR directory containing summary.json files (repeatable).",
    )
    parser.add_argument("--output-dir", required=True)
    return parser


def _discover_summary_paths(inputs: list[str]) -> list[Path]:
    paths: list[Path] = []
    for item in inputs:
        path = Path(item).expanduser().resolve()
        if path.is_file():
            paths.append(path)
            continue
        if path.is_dir():
            paths.extend(sorted(path.glob("**/summary.json")))
    dedup: dict[str, Path] = {}
    for path in paths:
        dedup[str(path)] = path
    return list(dedup.values())


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    output_dir = Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    summary_paths = _discover_summary_paths(args.input)
    rows: list[VariantRow] = []
    for path in summary_paths:
        rows.extend(_extract_rows(path))

    report = {
        "generated_at": __import__("datetime").datetime.utcnow().isoformat() + "Z",
        "suite_sources": [str(path) for path in summary_paths],
        "metrics": {
            "black_box": _variant_metrics(rows, "black_box"),
            "white_box": _variant_metrics(rows, "white_box"),
        },
        "deltas": _deltas(rows),
    }

    json_path = output_dir / "aggregate.json"
    json_path.write_text(json.dumps({"report": report, "rows": [row.as_dict() for row in rows]}, indent=2), encoding="utf-8")

    csv_path = output_dir / "rows.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "suite",
                "case_id",
                "variant",
                "run_id",
                "status",
                "elapsed_seconds",
                "vectors",
                "findings",
                "browser_routes",
                "gt_total",
                "gt_matched",
                "success",
                "report_path",
                "comprehensive_report_path",
                "timeline_csv_path",
            ],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(row.as_dict())

    md_path = output_dir / "aggregate.md"
    md_path.write_text(_render_markdown(report, rows), encoding="utf-8")

    print(
        json.dumps(
            {
                "ok": True,
                "inputs": [str(path) for path in summary_paths],
                "rows": len(rows),
                "aggregate_json": str(json_path),
                "aggregate_csv": str(csv_path),
                "aggregate_md": str(md_path),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
