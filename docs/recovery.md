# Recovery

## Common Cases

1. Worker crash during phase:
   - restart API process
   - enqueue/retry run
   - expired lease can be reclaimed
2. Blocked run:
   - inspect approvals/events
   - resolve operator action
   - retry or replan
3. Transient failure:
   - retry attempt is auto-scheduled for retryable classes
4. Permanent failure:
   - review error class and terminal/report artifacts
   - create operator note and replan

## Useful Endpoints

- `GET /api/v1/runs/{run_id}/graph`
- `GET /api/v1/runs/{run_id}/phase`
- `GET /api/v1/runs/{run_id}/events`
- `GET /api/v1/runs/{run_id}/terminal`
- `GET /api/v1/system/status`
