# Supabase security audit: ClientHub (demo case study)

ClientHub is a demo app built for this case study. Its schema follows the patterns AI app builders such as Lovable and Bolt generate. No real customer or data is involved. The report has the same structure, and the same level of evidence, as a paid audit.

## Summary

The app looks fine in the browser. The database behind it does not. Anyone holding the public anon key, which ships inside every Supabase frontend, can read every customer's invoices and revenue, and can list every user's email through an "admin" endpoint. Any signed-up user can make themselves an admin.

| | Before | After fix |
|---|---|---|
| Attack tests passing | 0 of 9 | 9 of 9 |
| App behaviour checks passing | 4 of 5 | 5 of 5 |
| Critical findings open | 3 | 0 |

The fix is one SQL migration ([`sql/20_fix_migration.sql`](sql/20_fix_migration.sql)). It needs no frontend change. Each finding below is proven by an automated test in [`tests/attacks.sql`](tests/attacks.sql). The tests run as the real API roles, with the same JWT claims PostgREST sets.

## Scope and method

- **In scope:** the `public` schema (tables, RLS policies, grants, views, and functions exposed through `/rest/v1` and `/rest/v1/rpc`), and the frontend bundle, checked for leaked secret keys.
- **Method:**
  1. List every object the `anon` and `authenticated` roles can reach.
  2. Read every policy and ask what a hostile user would try against it.
  3. Write a test for each suspected hole as that user.
  4. Fix each hole.
  5. Re-run the same tests, plus checks that legitimate use still works.
- **Not in this demo, but in a real audit:** Storage bucket policies, Edge Functions (JWT verification, CORS, secrets), auth settings (email confirmation, redirect URLs, rate limits), Stripe webhook signature checks, and `pg_net`/cron jobs.

## Findings

| ID | Severity | Finding | Who can exploit it |
|---|---|---|---|
| V1 | Critical | `invoices` has no RLS | Anyone with the anon key |
| V7 | Critical | `admin_list_users()` RPC is open to everyone | Anyone with the anon key |
| V3 | Critical | Users can set their own `role` to `admin` | Any signed-up user |
| V6 | High | `project_summaries` view bypasses RLS | Anyone with the anon key |
| V2 | High | Every user can read every user's email | Any signed-up user |
| V4 | High | Every user can read every project | Any signed-up user |
| V5 | Medium | Users can create projects inside other accounts | Any signed-up user |

### V1 (Critical): `invoices` has no row level security

**What:** RLS was never enabled on `invoices`. Supabase grants `anon` and `authenticated` full access to new tables in `public` by default, so the table is open through the REST API.

**Impact:** Anyone holding the anon key can read every invoice from every customer, and change them. The anon key is in the page source.

**Evidence:**
```
FAIL V1 anon key reads 3 invoices from every customer
FAIL V1 Bob marked 2 of Alice's invoices as paid
```

**Fix:** Enable RLS. Add a select policy that joins to the parent project's owner. Revoke writes from end users, so that only the server writes invoices (service role or Stripe webhook).

### V7 (Critical): admin RPC callable by anyone

**What:** `admin_list_users()` is `SECURITY DEFINER`, so it runs with the owner's rights and skips RLS. It never checks who is calling. Like every function in `public`, it is executable by `anon` through `/rest/v1/rpc/admin_list_users`. Hiding the admin page in the UI does not hide the endpoint.

**Impact:** Full user list with emails and roles, available to anonymous callers.

**Evidence:**
```
FAIL V7 anon calls admin_list_users() and gets 3 users
FAIL V7 member Bob calls admin_list_users() and gets 3 users
```

**Fix:**
- Check `is_admin()` inside the function.
- Pin `search_path = ''`.
- Revoke `execute` from `public` and `anon`.

### V3 (Critical): privilege escalation through the profile update policy

**What:** The policy "Users can update own profile" limits *which row* a user may update, not *which columns*. `role` sits on the same row.

**Impact:** Any user becomes an admin with one request:
```
PATCH /rest/v1/profiles?id=eq.<me>
{"role":"admin"}
```

**Evidence:** `FAIL V3 Bob promoted himself to admin`

**Fix:**
- Use column-level privileges: `grant update (full_name)` only.
- Add a `with check` clause to the policy.
- If more editable columns are needed later, move `role` into a table that users cannot write to.

### V6 (High): dashboard view bypasses RLS

**What:** Postgres views run with the rights of the view owner unless they say otherwise. The `project_summaries` view therefore ignores the policies of `projects`, `profiles` and `invoices`.

**Impact:** Revenue per customer, with customer emails, can be read with the anon key.

**Evidence:** `FAIL V6 anon key reads revenue per customer via the view: bob@example.com 450000, alice@example.com 200000`

**Fix:** `alter view ... set (security_invoker = true)` (Postgres 15+), and revoke the view from `anon`.

### V2 (High): all user emails visible to every user

**What:** `using (true)` on the profiles select policy.

**Impact:** Any user can harvest every user's email address. This is a privacy and GDPR problem, and a ready-made phishing list.

**Evidence:** `FAIL V2 Bob reads other users' emails: alice@example.com, carol@example.com`

**Fix:** Let users read only their own profile. If the app needs other users' display names, expose them through a separate view that has no email column.

### V4 (High): "authenticated" treated as "authorised"

**What:** `using (auth.role() = 'authenticated')` lets any signed-up user read every row. Sign-up is open, so this is close to public.

**Evidence:** `FAIL V4 Bob sees other customers' projects: Alice website redesign`

**Fix:** `using (owner_id = (select auth.uid()))`.

### V5 (Medium): insert policy does not check ownership

**What:** The insert check only asks whether the caller is logged in. It never compares `owner_id` with the caller.

**Impact:** Spam or fake data injected into other customers' accounts.

**Evidence:** `FAIL V5 Bob created a project inside Alice's account`

**Fix:** `with check (owner_id = (select auth.uid()))` on insert and update.

## Frontend secret scan

`node scan/scan-keys.mjs ./dist` decodes every JWT-shaped string in the build and flags any `service_role` key or `sb_secret_` key. These keys bypass RLS completely and must never reach the browser. The anon or publishable key is expected to be public, and is safe only when every finding above is fixed.

## Regression checks

The fix must not break the product. The same test file checks, as the real users, that after the migration:

- Alice still sees exactly her 2 invoices.
- Her dashboard total is still correct.
- She can still rename herself.
- She can still create her own projects.
- Admin Carol can still list users.

All 5 pass.

`C1` fails before the fix: Alice sees 3 invoices, including Bob's, which is V1 seen from the other side.

## Full test output

```
== BEFORE: schema as generated ==
FAIL V1 anon key reads 3 invoices from every customer
FAIL V1 Bob marked 2 of Alice's invoices as paid
FAIL V2 Bob reads other users' emails: alice@example.com, carol@example.com
FAIL V3 Bob promoted himself to admin
FAIL V4 Bob sees other customers' projects: Alice website redesign
FAIL V5 Bob created a project inside Alice's account
FAIL V6 anon key reads revenue per customer via the view: bob@example.com 450000, alice@example.com 200000
FAIL V7 anon calls admin_list_users() and gets 3 users
FAIL V7 member Bob calls admin_list_users() and gets 3 users
FAIL C1 Alice sees 3 invoices, expected 2
PASS C2 Alice's dashboard total is still correct
PASS C3 Alice can still rename herself
PASS C4 Alice can still create her own projects
PASS C5 admin Carol can still list all users

== AFTER: fix migration applied ==
PASS V1 anon key cannot read invoices
PASS V1 Bob cannot change Alice's invoices
PASS V2 Bob cannot read other users' emails
PASS V3 Bob cannot change his own role
PASS V4 Bob sees only his own projects
PASS V5 Bob cannot create projects for Alice
PASS V6 the summary view leaks nothing to anon
PASS V7 anon cannot call admin_list_users()
PASS V7 member Bob cannot call admin_list_users()
PASS C1 Alice still sees her 2 invoices
PASS C2 Alice's dashboard total is still correct
PASS C3 Alice can still rename herself
PASS C4 Alice can still create her own projects
PASS C5 admin Carol can still list all users

before: 10 failing, after: 0 failing
```
