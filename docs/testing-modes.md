# Black-Box And White-Box Testing

Vantix supports two assessment modes that intentionally produce different kinds of evidence. Both modes are for authorized testing only.

## Black-Box Mode

Black-box runs start with an in-scope target and no attached source tree. Vantix builds the assessment from externally observable behavior:

- network recon and service fingerprints
- browser route discovery, DOM snapshots, screenshots, and session state
- API traffic, forms, parameters, headers, and runtime responses
- CVE and product-intel enrichment tied to observed services
- bounded validation probes with artifact-backed proof

Black-box findings are runtime-first. A finding should appear in the report only when Vantix has evidence from the target, a proof artifact, and enough context for a reviewer to reproduce or reject it.

Use black-box mode when source is unavailable, when testing deployed exposure, or when the operator wants to measure what an external assessor can prove from the running system alone.

## White-Box Mode

White-box runs attach source through one of the supported source inputs:

- local path
- GitHub URL and optional ref
- staged source upload

Vantix still validates against the running target, but source analysis adds file/line-backed candidates for reviewer and agent follow-up. Typical source-backed candidates include:

- raw SQL or ORM query interpolation
- unsafe HTML trust decisions
- SSRF-capable URL fetches
- XML external entity expansion
- unsafe YAML/parser usage
- authentication and authorization trust-boundary mistakes
- source comments or challenge markers that identify risky code paths

White-box source candidates are not counted as validated exploit findings until runtime validation proves impact. The report keeps them in a separate **White-Box Source Analysis** section so reviewers can distinguish proven behavior from source-backed leads.

## Report Semantics

Vantix reports separate evidence by confidence class:

| Report item | Meaning | Reviewer action |
| --- | --- | --- |
| Validated finding | Runtime behavior was observed and captured in evidence artifacts. | Review PoC, artifact body, risk, and remediation. |
| Source candidate | Source code suggests a risky sink, weak trust boundary, or unsafe parser/config path. | Validate against the deployed target or mark as accepted source risk. |
| Negative evidence | A hypothesis was tested and did not validate under current constraints. | Use to suppress duplicates and avoid repeated weak attempts. |
| Artifact review | Full HTTP/body/screenshot/source evidence embedded or linked from the finding. | Inspect raw proof without leaving the report package. |

## Benchmark Examples

The repository includes sanitized OWASP Juice Shop lab artifacts that demonstrate both modes:

- [Black-box reference HTML report](examples/juice-shop-blackbox-report.html)
- [White-box reference HTML report](examples/juice-shop-whitebox-report.html)
- [Animated UI capture](../juiceblackbox.svg)

The black-box benchmark demonstrates external runtime validation. The white-box benchmark demonstrates the additional source-candidate layer, including a dedicated source-analysis report section with file/line evidence.

## Practical Guidance

Run black-box first when the goal is external proof and minimal assumptions. Run white-box when source is available and the objective includes deeper sink discovery, developer remediation, or explaining why a vulnerability exists. Compare both runs to identify gaps: black-box-only findings indicate behavior that source analysis did not prioritize; white-box-only candidates indicate code paths needing validation or triage.
