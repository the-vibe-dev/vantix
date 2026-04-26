from __future__ import annotations

from datetime import datetime, timezone

from secops.db import SessionLocal
from secops.models import Artifact, Fact, RunMessage, WorkspaceRun


class CvePhaseMixin:
    """CVE-analysis researcher phase, including quick-scan gating.

    Extracted from ExecutionManager. Relies on ``self.cve``, ``self.nas``,
    ``self.events`` and helpers (``_task_by_kind``, ``_create_agent_session``,
    ``_set_role_status``, ``_create_approval``, ``_set_vantix_task_status``,
    ``_write_memory``) from peer mixins.
    """

    def _phase_cve(self, run_id: str) -> None:
        with SessionLocal() as db:
            run = db.get(WorkspaceRun, run_id)
            if run is None or not self._check_controls(db, run):
                return
            task = self._task_by_kind(db, run.id, "cve-analysis")
            if task.status == "completed":
                return
            if bool((run.config_json or {}).get("quick_scan_gate_pending")):
                run.status = "blocked"
                self.events.emit(
                    db,
                    run.id,
                    "terminal",
                    "[cve] waiting for operator approval to continue beyond quick scan",
                    level="warning",
                    payload={"agent": "researcher"},
                )
                self._create_approval(
                    db,
                    run.id,
                    title="Recon complete: continue beyond quick scan",
                    detail="Recon completed successfully. Approve to continue with CVE analysis, orchestration, and reporting phases.",
                    reason="quick-scan-gate",
                )
                db.commit()
                return
            paths = self.nas.for_workspace(run.workspace_id)
            session = self._create_agent_session(db, run.id, "researcher", "Researcher Sidecar", paths)
            self._set_role_status(db, run.id, "researcher", "running")
            db.commit()
            results = []
            errors = []
            services = run.config_json.get("services", [])
            cve_hits = 0
            for service in services:
                try:
                    response = self.cve.search(vendor=service, product=service, always_search_external=True, live_limit=500)
                except Exception as exc:  # noqa: BLE001
                    response = {"source": "cve-search", "query": service, "results": [], "error": str(exc)}
                    errors.append({"service": service, "error": str(exc)})
                    self.events.emit(
                        db,
                        run.id,
                        "phase",
                        f"CVE lookup failed for {service}: {exc}",
                        level="warning",
                        agent_session_id=session.id,
                    )
                results.append(response)
                live_meta = dict(response.get("live") or {})
                live_attempted = bool(live_meta.get("attempted"))
                live_upserted = int(live_meta.get("upserted", 0) or 0)
                live_errors = [str(item) for item in (live_meta.get("errors") or [])]
                live_sources = [str(item) for item in (live_meta.get("sources") or [])]
                db.add(
                    Fact(
                        run_id=run.id,
                        source="cve-search",
                        kind="intel",
                        value=f"{service}: live attempted={live_attempted} upserted={live_upserted}",
                        confidence=0.8 if live_upserted > 0 else 0.6,
                        tags=["intel", "cve", service],
                        metadata_json={
                            "service": service,
                            "live_attempted": live_attempted,
                            "live_upserted": live_upserted,
                            "live_sources": live_sources,
                            "live_errors": live_errors,
                            "result_count": len(response.get("results") or []),
                        },
                    )
                )
                db.add(
                    RunMessage(
                        run_id=run.id,
                        role="system",
                        author="System",
                        content=(
                            f"CVE search `{service}`: {len(response.get('results') or [])} local result(s); "
                            f"external attempted={live_attempted}, upserted={live_upserted}, errors={len(live_errors)}."
                        ),
                        metadata_json={
                            "phase": "cve-analysis",
                            "service": service,
                            "live": live_meta,
                        },
                    )
                )
                cve_hits += len(response.get("results", []) or [])
                for top in response.get("results", [])[:5]:
                    db.add(
                        Fact(
                            run_id=run.id,
                            source="cve-search",
                            kind="cve",
                            value=top.get("id", ""),
                            confidence=float(top.get("cvss", 0) or 0),
                            tags=[service, "cve"],
                            metadata_json=top,
                        )
                    )
                db.commit()
            cve_path = paths.facts / "cve_results.json"
            paths.write_json(cve_path, results)
            session.status = "completed"
            session.completed_at = datetime.now(timezone.utc)
            self._set_role_status(db, run.id, "researcher", "completed")
            self._set_role_status(db, run.id, "vector_store", "completed")
            task.status = "completed"
            task.result_json = {"queries": len(results), "errors": errors, "hits": cve_hits}
            self._set_vantix_task_status(db, run.id, "research", "completed", {"queries": len(results), "errors": len(errors), "source_phase": "cve-analysis"})
            self._set_vantix_task_status(db, run.id, "vector-store", "completed", {"queries": len(results), "source_phase": "cve-analysis"})
            self.events.emit(db, run.id, "phase", f"CVE analysis completed: {len(results)} queries", agent_session_id=session.id)
            db.add(
                RunMessage(
                    run_id=run.id,
                    role="system",
                    author="System",
                    content=f"CVE search completed: {len(results)} service queries, {cve_hits} matches, {len(errors)} errors.",
                    metadata_json={"phase": "cve-analysis", "queries": len(results), "hits": cve_hits, "errors": len(errors)},
                )
            )
            self._write_memory(db, run, mode="phase", phase="cve-analysis", done=[f"cve queries={len(results)}"], files=[str(cve_path)], next_action="primary orchestration")
            db.add(Artifact(run_id=run.id, kind="cve-results", path=str(cve_path), metadata_json={"queries": len(results)}))
            db.commit()
