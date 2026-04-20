# Database Operations

SecOps ships with SQLite by default and supports Postgres as an opt-in backend
via `SECOPS_DATABASE_URL`. Choose based on deployment size:

- **SQLite (default)**: single-node development or small labs. No server to run.
  Schema is bootstrapped automatically on startup via SQLAlchemy `create_all`.
- **Postgres**: multi-worker deployments, or when concurrent phase claims need
  row-level locks (`SELECT ... FOR UPDATE SKIP LOCKED`).

## Provisioning Postgres

1. Create the database and user:
   ```sql
   CREATE USER secops WITH PASSWORD 'change-me';
   CREATE DATABASE secops OWNER secops;
   GRANT ALL PRIVILEGES ON DATABASE secops TO secops;
   ```
2. Export the URL in the environment SecOps will run under:
   ```
   SECOPS_DATABASE_URL=postgresql+psycopg://secops:change-me@db-host:5432/secops
   ```
3. Apply migrations before first boot:
   ```
   alembic upgrade head
   ```
   The app also runs `alembic upgrade head` at startup when the dialect is not
   sqlite, so a fresh database will be migrated automatically when the process
   starts. Running it manually ahead of time lets you verify the schema before
   traffic lands.

## Migrations

- All schema changes go through Alembic revisions under `alembic/versions/`.
- Create a new revision:
  ```
  alembic revision --autogenerate -m "short description"
  ```
  Review the generated file carefully — autogenerate misses type changes,
  server defaults, and check constraints.
- Batch-op rendering is enabled automatically when the URL points at SQLite so
  that migrations remain portable across both backends.

## Rollback

Alembic supports stepping back one revision at a time:

```
alembic downgrade -1
```

For production Postgres rollbacks, run downgrades inside a transaction whenever
possible and confirm application code has been reverted first. Never downgrade
past a revision that introduced data the running code depends on.

## Concurrency

On Postgres, the workflow phase claim loop uses `SELECT ... FOR UPDATE SKIP
LOCKED LIMIT 1` so concurrent workers never contend for the same row. On SQLite
the loop falls back to an optimistic candidate-IDs + targeted `UPDATE` pattern;
this is safe because SQLite serializes writes at the database level.

If you scale beyond a handful of workers, switch to Postgres — SQLite's global
write lock will throttle you regardless of Python-level concurrency.

## Backups

Postgres: use `pg_dump` on a schedule and verify restores monthly. SQLite:
copy the database file while the service is stopped (or use `sqlite3 .backup`
while online).
