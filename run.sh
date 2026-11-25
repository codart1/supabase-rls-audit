#!/usr/bin/env bash
# Runs the attack tests twice: against the vulnerable schema, then after the
# fix migration. Needs psql and a Postgres 15+ server you can create
# databases on (the default is a throwaway Docker container, see README).
#
#   PGURL=postgres://postgres:postgres@localhost:54329/postgres ./run.sh
set -uo pipefail
cd "$(dirname "$0")"

PGURL="${PGURL:-postgres://postgres:postgres@localhost:54329/postgres}"
DB=rls_case_study
DBURL="${PGURL%/*}/$DB"

PGOPTIONS="-c client_min_messages=warning" psql "$PGURL" -qX -v ON_ERROR_STOP=1 -c "drop database if exists $DB" -c "create database $DB" >/dev/null || exit 1
for f in sql/00_supabase_shim.sql sql/10_app_before.sql sql/15_seed.sql; do
  psql "$DBURL" -qX -v ON_ERROR_STOP=1 -f "$f" >/dev/null || exit 1
done

run_tests() {
  psql "$DBURL" -qX -f tests/attacks.sql 2>&1 | sed -n 's/^.*NOTICE:  //p'
}

echo "== BEFORE: schema as generated =="
before=$(run_tests); echo "$before"

psql "$DBURL" -qX -v ON_ERROR_STOP=1 -f sql/20_fix_migration.sql >/dev/null || exit 1

echo
echo "== AFTER: fix migration applied =="
after=$(run_tests); echo "$after"

echo
echo "before: $(grep -c '^FAIL' <<<"$before") failing, after: $(grep -c '^FAIL' <<<"$after") failing"
! grep -q '^FAIL' <<<"$after"
