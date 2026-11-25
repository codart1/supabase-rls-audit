# Supabase RLS audit: a worked example

A demo of how I audit AI-generated (Lovable / Bolt style) Supabase apps before launch.

**ClientHub** is a small demo client portal with 7 security holes that are common in generated Supabase schemas: a table with no RLS, users who can make themselves admin, a view and an RPC that bypass RLS, and more. No real customer or data is involved.

- [`AUDIT_REPORT.md`](AUDIT_REPORT.md): the report, in the same format a client receives.
- `sql/10_app_before.sql`: the vulnerable schema.
- `sql/20_fix_migration.sql`: the fix, as a single migration.
- `tests/attacks.sql`: 9 attack tests run as real API callers (role and JWT claims set as PostgREST does), plus 5 checks that the app still works.
- `scan/scan-keys.mjs`: finds `service_role` / `sb_secret_` keys in a frontend build.
- `sql/00_supabase_shim.sql`: recreates Supabase's roles, `auth.uid()` and default grants on plain Postgres, so everything runs locally.

## Run it

Needs `psql` and Docker:

```bash
docker run -d --name rls-pg -e POSTGRES_PASSWORD=postgres -p 54329:5432 postgres:16
./run.sh                        # prints results before and after the fix; exits 0 if the fix passes
node scan/scan-keys.mjs ./dist  # scan a frontend build
docker rm -f rls-pg
```

The result is 10 failures before the fix and 0 after.

To use another Postgres server: `PGURL=postgres://user:pass@host:port/postgres ./run.sh`.

## License

MIT
