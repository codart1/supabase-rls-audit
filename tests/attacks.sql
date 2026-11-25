-- Attack tests. Each block runs as a real API caller would (role + JWT
-- claims, exactly what PostgREST sets) inside a transaction that is rolled
-- back, and prints one line:
--   PASS  the attack was blocked / the legitimate action still works
--   FAIL  the attack succeeded (data leaked or changed)
-- Bob (2222...) is the attacker; Alice (1111...) is the victim; Carol
-- (3333...) is a legitimate admin.

\set QUIET on
\set ON_ERROR_STOP off
set client_min_messages = notice;

-- V1 -----------------------------------------------------------------------
begin;
set local role anon;
select set_config('request.jwt.claims', '{"role":"anon"}', true) \g /dev/null
do $$ declare n int; begin
  select count(*) into n from public.invoices;
  if n > 0 then raise notice 'FAIL V1 anon key reads % invoices from every customer', n;
  else raise notice 'PASS V1 anon key cannot read invoices'; end if;
exception when insufficient_privilege then raise notice 'PASS V1 anon key cannot read invoices';
end $$;
rollback;

begin;
set local role authenticated;
select set_config('request.jwt.claims', '{"sub":"22222222-2222-2222-2222-222222222222","role":"authenticated"}', true) \g /dev/null
do $$ declare n int; begin
  update public.invoices set status = 'paid'
   where project_id in (select id from public.projects where name like 'Alice%');
  get diagnostics n = row_count;
  if n > 0 then raise notice 'FAIL V1 Bob marked % of Alice''s invoices as paid', n;
  else raise notice 'PASS V1 Bob cannot change Alice''s invoices'; end if;
exception when insufficient_privilege then raise notice 'PASS V1 Bob cannot change Alice''s invoices';
end $$;
rollback;

-- V2 -----------------------------------------------------------------------
begin;
set local role authenticated;
select set_config('request.jwt.claims', '{"sub":"22222222-2222-2222-2222-222222222222","role":"authenticated"}', true) \g /dev/null
do $$ declare e text; begin
  select string_agg(email, ', ') into e from public.profiles where id <> auth.uid();
  if e is not null then raise notice 'FAIL V2 Bob reads other users'' emails: %', e;
  else raise notice 'PASS V2 Bob cannot read other users'' emails'; end if;
exception when insufficient_privilege then raise notice 'PASS V2 Bob cannot read other users'' emails';
end $$;
rollback;

-- V3 -----------------------------------------------------------------------
begin;
set local role authenticated;
select set_config('request.jwt.claims', '{"sub":"22222222-2222-2222-2222-222222222222","role":"authenticated"}', true) \g /dev/null
do $$ declare n int; begin
  update public.profiles set role = 'admin' where id = auth.uid();
  get diagnostics n = row_count;
  if n > 0 then raise notice 'FAIL V3 Bob promoted himself to admin';
  else raise notice 'PASS V3 Bob cannot change his own role'; end if;
exception when insufficient_privilege then raise notice 'PASS V3 Bob cannot change his own role';
end $$;
rollback;

-- V4 -----------------------------------------------------------------------
begin;
set local role authenticated;
select set_config('request.jwt.claims', '{"sub":"22222222-2222-2222-2222-222222222222","role":"authenticated"}', true) \g /dev/null
do $$ declare e text; begin
  select string_agg(name, ', ') into e from public.projects where owner_id <> auth.uid();
  if e is not null then raise notice 'FAIL V4 Bob sees other customers'' projects: %', e;
  else raise notice 'PASS V4 Bob sees only his own projects'; end if;
exception when insufficient_privilege then raise notice 'PASS V4 Bob sees only his own projects';
end $$;
rollback;

-- V5 -----------------------------------------------------------------------
begin;
set local role authenticated;
select set_config('request.jwt.claims', '{"sub":"22222222-2222-2222-2222-222222222222","role":"authenticated"}', true) \g /dev/null
do $$ begin
  insert into public.projects (owner_id, name)
  values ('11111111-1111-1111-1111-111111111111', 'Spam project');
  raise notice 'FAIL V5 Bob created a project inside Alice''s account';
exception when insufficient_privilege then raise notice 'PASS V5 Bob cannot create projects for Alice';
end $$;
rollback;

-- V6 -----------------------------------------------------------------------
begin;
set local role anon;
select set_config('request.jwt.claims', '{"role":"anon"}', true) \g /dev/null
do $$ declare e text; begin
  select string_agg(owner_email || ' ' || total_cents, ', ') into e from public.project_summaries;
  if e is not null then raise notice 'FAIL V6 anon key reads revenue per customer via the view: %', e;
  else raise notice 'PASS V6 the summary view leaks nothing to anon'; end if;
exception when insufficient_privilege then raise notice 'PASS V6 the summary view leaks nothing to anon';
end $$;
rollback;

-- V7 -----------------------------------------------------------------------
begin;
set local role anon;
select set_config('request.jwt.claims', '{"role":"anon"}', true) \g /dev/null
do $$ declare n int; begin
  select count(*) into n from public.admin_list_users();
  raise notice 'FAIL V7 anon calls admin_list_users() and gets % users', n;
exception when insufficient_privilege then raise notice 'PASS V7 anon cannot call admin_list_users()';
end $$;
rollback;

begin;
set local role authenticated;
select set_config('request.jwt.claims', '{"sub":"22222222-2222-2222-2222-222222222222","role":"authenticated"}', true) \g /dev/null
do $$ declare n int; begin
  select count(*) into n from public.admin_list_users();
  raise notice 'FAIL V7 member Bob calls admin_list_users() and gets % users', n;
exception when insufficient_privilege then raise notice 'PASS V7 member Bob cannot call admin_list_users()';
end $$;
rollback;

-- Regression checks: the fix must not break the app ------------------------
begin;
set local role authenticated;
select set_config('request.jwt.claims', '{"sub":"11111111-1111-1111-1111-111111111111","role":"authenticated"}', true) \g /dev/null
do $$ declare n int; begin
  select count(*) into n from public.invoices;
  if n = 2 then raise notice 'PASS C1 Alice still sees her 2 invoices';
  else raise notice 'FAIL C1 Alice sees % invoices, expected 2', n; end if;
exception when others then raise notice 'FAIL C1 Alice cannot read her invoices: %', sqlerrm;
end $$;
do $$ declare n int; begin
  select total_cents into n from public.project_summaries where owner_id = auth.uid();
  if n = 200000 then raise notice 'PASS C2 Alice''s dashboard total is still correct';
  else raise notice 'FAIL C2 Alice''s dashboard total is %, expected 200000', n; end if;
exception when others then raise notice 'FAIL C2 Alice cannot read her dashboard: %', sqlerrm;
end $$;
do $$ declare n int; begin
  update public.profiles set full_name = 'Alice N.' where id = auth.uid();
  get diagnostics n = row_count;
  if n = 1 then raise notice 'PASS C3 Alice can still rename herself';
  else raise notice 'FAIL C3 Alice''s rename changed % rows', n; end if;
exception when others then raise notice 'FAIL C3 Alice cannot rename herself: %', sqlerrm;
end $$;
do $$ begin
  insert into public.projects (owner_id, name) values (auth.uid(), 'Alice new project');
  raise notice 'PASS C4 Alice can still create her own projects';
exception when others then raise notice 'FAIL C4 Alice cannot create a project: %', sqlerrm;
end $$;
rollback;

begin;
set local role authenticated;
select set_config('request.jwt.claims', '{"sub":"33333333-3333-3333-3333-333333333333","role":"authenticated"}', true) \g /dev/null
do $$ declare n int; begin
  select count(*) into n from public.admin_list_users();
  if n = 3 then raise notice 'PASS C5 admin Carol can still list all users';
  else raise notice 'FAIL C5 admin Carol gets % users, expected 3', n; end if;
exception when others then raise notice 'FAIL C5 admin Carol cannot list users: %', sqlerrm;
end $$;
rollback;
