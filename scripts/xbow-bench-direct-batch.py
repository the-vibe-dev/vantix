#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup


FLAG_RE = re.compile(r"FLAG\{[0-9a-fA-F]{64}\}")


@dataclass
class Endpoint:
    service: str
    container_port: int
    host_port: int
    url: str


@dataclass
class BenchResult:
    benchmark_id: str
    status: str
    ready: bool
    solved: bool
    flag: str
    elapsed_launch_to_ready_s: float
    elapsed_launch_to_finish_s: float
    notes: str = ""
    endpoints: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "benchmark_id": self.benchmark_id,
            "status": self.status,
            "ready": self.ready,
            "solved": self.solved,
            "flag": self.flag,
            "elapsed_launch_to_ready_s": round(self.elapsed_launch_to_ready_s, 3),
            "elapsed_launch_to_finish_s": round(self.elapsed_launch_to_finish_s, 3),
            "notes": self.notes,
            "endpoints": self.endpoints,
        }


class DirectBenchRunner:
    def __init__(
        self,
        map_path: Path,
        output_dir: Path,
        per_target_timeout_s: int,
        ready_timeout_s: int,
        start_from: str = "",
        limit: int = 0,
    ) -> None:
        self.map_path = map_path
        self.output_dir = output_dir
        self.per_target_timeout_s = per_target_timeout_s
        self.ready_timeout_s = ready_timeout_s
        self.start_from = start_from
        self.limit = limit
        self.results: list[BenchResult] = []
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.jsonl_path = self.output_dir / "results.jsonl"
        self.summary_path = self.output_dir / "summary.json"
        self.csv_path = self.output_dir / "results.csv"

    def load_map(self) -> list[tuple[str, list[Endpoint]]]:
        rows = [json.loads(line) for line in self.map_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        buckets: dict[str, list[Endpoint]] = {}
        for row in rows:
            bench = row["benchmark_id"]
            url = row.get("url", "")
            ep = Endpoint(
                service=row.get("service", ""),
                container_port=int(row.get("container_port", 0)),
                host_port=int(row.get("host_port", 0)),
                url=url if str(url).startswith("http") else f"http://{url}",
            )
            buckets.setdefault(bench, []).append(ep)
        items = sorted(buckets.items(), key=lambda x: x[0])
        if self.start_from:
            items = [x for x in items if x[0] >= self.start_from]
        if self.limit > 0:
            items = items[: self.limit]
        return items

    def run(self) -> int:
        if self.jsonl_path.exists():
            self.jsonl_path.unlink()
        benches = self.load_map()
        for idx, (bench_id, endpoints) in enumerate(benches, start=1):
            result = self._run_one(idx, len(benches), bench_id, endpoints)
            self.results.append(result)
            self._append_result(result)
            self._write_summary()
        self._write_csv()
        self._write_summary()
        return 0

    def _append_result(self, result: BenchResult) -> None:
        with self.jsonl_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(result.as_dict(), ensure_ascii=True) + "\n")

    def _write_csv(self) -> None:
        with self.csv_path.open("w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(
                fh,
                fieldnames=[
                    "benchmark_id",
                    "status",
                    "ready",
                    "solved",
                    "flag",
                    "elapsed_launch_to_ready_s",
                    "elapsed_launch_to_finish_s",
                    "notes",
                    "endpoints",
                ],
            )
            writer.writeheader()
            for row in self.results:
                d = row.as_dict()
                d["endpoints"] = " ".join(row.endpoints)
                writer.writerow(d)

    def _write_summary(self) -> None:
        total = len(self.results)
        solved = sum(1 for r in self.results if r.solved)
        ready = sum(1 for r in self.results if r.ready)
        pass_rate = (solved / total * 100.0) if total else 0.0
        summary = {
            "total": total,
            "ready": ready,
            "solved": solved,
            "pass_rate_pct": round(pass_rate, 3),
            "target_pass_pct": 88.0,
            "meets_target": pass_rate >= 88.0,
            "generated_at_epoch": time.time(),
            "results_path": str(self.jsonl_path),
        }
        self.summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    def _run_one(self, idx: int, total: int, bench_id: str, endpoints: list[Endpoint]) -> BenchResult:
        print(f"[{idx}/{total}] {bench_id}: launching", flush=True)
        t0 = time.perf_counter()
        launch_ok, launch_note = self._launch_benchmark(bench_id)
        if not launch_ok:
            t1 = time.perf_counter()
            return BenchResult(
                benchmark_id=bench_id,
                status="launch_failed",
                ready=False,
                solved=False,
                flag="",
                elapsed_launch_to_ready_s=0.0,
                elapsed_launch_to_finish_s=t1 - t0,
                notes=launch_note,
                endpoints=[ep.url for ep in endpoints],
            )

        ready, ready_ep = self._wait_ready(endpoints, self.ready_timeout_s)
        t_ready = time.perf_counter()
        if not ready:
            self._stop_benchmark(bench_id)
            return BenchResult(
                benchmark_id=bench_id,
                status="not_ready",
                ready=False,
                solved=False,
                flag="",
                elapsed_launch_to_ready_s=t_ready - t0,
                elapsed_launch_to_finish_s=t_ready - t0,
                notes="endpoint did not become reachable",
                endpoints=[ep.url for ep in endpoints],
            )

        flag = ""
        notes = ""
        status = "unsolved"
        try:
            flag, notes = self._probe_for_flag(ready_ep.url, self.per_target_timeout_s)
            status = "solved" if flag else "unsolved"
        except Exception as exc:  # noqa: BLE001
            status = "probe_error"
            notes = str(exc)
        finally:
            self._stop_benchmark(bench_id)

        t_end = time.perf_counter()
        solved = bool(flag)
        print(
            f"[{idx}/{total}] {bench_id}: {status} ready={ready} "
            f"launch->ready={t_ready - t0:.1f}s launch->finish={t_end - t0:.1f}s",
            flush=True,
        )
        return BenchResult(
            benchmark_id=bench_id,
            status=status,
            ready=ready,
            solved=solved,
            flag=flag,
            elapsed_launch_to_ready_s=t_ready - t0,
            elapsed_launch_to_finish_s=t_end - t0,
            notes=notes,
            endpoints=[ep.url for ep in endpoints],
        )

    def _launch_benchmark(self, bench_id: str) -> tuple[bool, str]:
        cmd = ["bash", "scripts/devwork-bench-run-fixed.sh", bench_id]
        run = subprocess.run(cmd, capture_output=True, text=True, check=False, cwd=".")
        if run.returncode != 0:
            return False, (run.stderr or run.stdout).strip()[:1000]
        return True, "ok"

    def _stop_benchmark(self, bench_id: str) -> None:
        cmd = ["bash", "scripts/devwork-bench-run-fixed.sh", "--stop", bench_id]
        subprocess.run(cmd, capture_output=True, text=True, check=False, cwd=".")

    def _wait_ready(self, endpoints: list[Endpoint], timeout_s: int) -> tuple[bool, Endpoint]:
        deadline = time.time() + timeout_s
        with httpx.Client(verify=False, timeout=4.0, follow_redirects=True) as client:
            while time.time() < deadline:
                for ep in endpoints:
                    try:
                        res = client.get(ep.url)
                        if res.status_code < 500:
                            return True, ep
                    except Exception:
                        pass
                time.sleep(1.2)
        return False, endpoints[0]

    def _probe_for_flag(self, base_url: str, budget_s: int) -> tuple[str, str]:
        started = time.time()
        visited: set[str] = set()
        queue = [base_url]
        candidates = [
            "/",
            "/robots.txt",
            "/sitemap.xml",
            "/flag",
            "/flag.txt",
            "/admin",
            "/login",
            "/orders",
            "/dashboard",
            "/api",
            "/api/flag",
            "/debug",
            "/.env",
            "/phpinfo.php",
        ]
        with httpx.Client(verify=False, timeout=5.0, follow_redirects=True) as client:
            # seed deterministic paths first
            for p in candidates:
                queue.append(urljoin(base_url, p))

            while queue and (time.time() - started) < budget_s:
                url = queue.pop(0)
                if url in visited:
                    continue
                visited.add(url)
                try:
                    r = client.get(url)
                except Exception:
                    continue

                text = r.text or ""
                m = FLAG_RE.search(text)
                if m:
                    return m.group(0), f"found in GET {url}"

                # Try simple auth defaults when login-like form exists
                if ("<form" in text.lower()) and ("username" in text.lower() or "password" in text.lower()):
                    creds = [
                        {"username": "test", "password": "test"},
                        {"username": "admin", "password": "admin"},
                        {"username": "admin", "password": "password"},
                        {"username": "user", "password": "user"},
                        {"username": "test"},
                        {"username": "admin"},
                    ]
                    for cred in creds:
                        if (time.time() - started) >= budget_s:
                            break
                        try:
                            rr = client.post(url, data=cred)
                        except Exception:
                            continue
                        mm = FLAG_RE.search(rr.text or "")
                        if mm:
                            return mm.group(0), f"found after POST {url} with {cred}"
                        # follow a few linked pages after auth attempt
                        for link in self._extract_links(rr.text or "", rr.url):
                            if link not in visited and self._is_same_host(base_url, link):
                                queue.append(link)

                # parse links and enqueue
                for link in self._extract_links(text, r.url):
                    if link not in visited and self._is_same_host(base_url, link):
                        queue.append(link)

                # parse numeric object hints and do small idor sweep
                nums = set(int(x) for x in re.findall(r"\b(\d{2,8})\b", text))
                id_hints = re.findall(r"/[A-Za-z0-9_\-]+/\d{2,8}/[A-Za-z0-9_\-/]*", text)
                for hint in id_hints[:12]:
                    full = urljoin(base_url, hint)
                    for delta in (-3, -2, -1, 1, 2, 3, 10, 100):
                        if (time.time() - started) >= budget_s:
                            break
                        m2 = re.search(r"(\d{2,8})(?!.*\d)", full)
                        if not m2:
                            continue
                        orig = int(m2.group(1))
                        mutated = str(max(1, orig + delta))
                        probe = full[: m2.start(1)] + mutated + full[m2.end(1) :]
                        try:
                            rp = client.get(probe)
                        except Exception:
                            continue
                        mp = FLAG_RE.search(rp.text or "")
                        if mp:
                            return mp.group(0), f"found via idor probe {probe}"

                # small generic query parameter probes
                if nums:
                    base_path = str(r.url).split("?", 1)[0]
                    for n in list(nums)[:6]:
                        for key in ("id", "user_id", "order_id", "account_id"):
                            if (time.time() - started) >= budget_s:
                                break
                            for delta in (1, -1, 10, 100):
                                probe_id = max(1, n + delta)
                                probe = f"{base_path}?{key}={probe_id}"
                                try:
                                    rp = client.get(probe)
                                except Exception:
                                    continue
                                mp = FLAG_RE.search(rp.text or "")
                                if mp:
                                    return mp.group(0), f"found via param probe {probe}"

        return "", f"budget_exhausted visited={len(visited)}"

    @staticmethod
    def _is_same_host(base_url: str, candidate: str) -> bool:
        b = urlparse(base_url)
        c = urlparse(candidate)
        return (b.scheme, b.hostname, b.port) == (c.scheme, c.hostname, c.port)

    @staticmethod
    def _extract_links(html: str, current_url: str | httpx.URL) -> list[str]:
        out: list[str] = []
        try:
            soup = BeautifulSoup(html, "html.parser")
        except Exception:
            return out
        base = str(current_url)
        for tag in soup.find_all(["a", "link", "script", "form"]):
            attr = "href" if tag.name in {"a", "link"} else ("src" if tag.name == "script" else "action")
            val = tag.get(attr)
            if not val:
                continue
            out.append(urljoin(base, val))
        # also mine JS route strings
        for m in re.findall(r"['\"](/[^'\" ]{1,200})['\"]", html):
            out.append(urljoin(base, m))
        return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Direct in-session XBOW benchmark batch runner (no API, no nested Codex runs).")
    parser.add_argument(
        "--map",
        default="./artifacts/benchmarks/devwork_lan_map/endpoints.jsonl",
        help="Path to endpoints JSONL map",
    )
    parser.add_argument(
        "--out",
        default=f"./artifacts/benchmarks/runs/direct_{int(time.time())}",
        help="Output directory",
    )
    parser.add_argument("--per-target-timeout", type=int, default=180, help="Probe time budget per benchmark in seconds")
    parser.add_argument("--ready-timeout", type=int, default=120, help="Readiness timeout in seconds")
    parser.add_argument("--start-from", default="", help="Start from benchmark id")
    parser.add_argument("--limit", type=int, default=0, help="Run only first N after filtering")
    args = parser.parse_args()

    runner = DirectBenchRunner(
        map_path=Path(args.map),
        output_dir=Path(args.out),
        per_target_timeout_s=args.per_target_timeout,
        ready_timeout_s=args.ready_timeout,
        start_from=args.start_from,
        limit=args.limit,
    )
    return runner.run()


if __name__ == "__main__":
    raise SystemExit(main())

