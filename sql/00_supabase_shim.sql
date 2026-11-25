-- Local stand-in for the parts of Supabase that RLS depends on.
-- Only used when running against plain Postgres. Do NOT run this on a real
-- Supabase project: these objects already exist there.
--
-- What it reproduces:
--   * the anon / authenticated / service_role roles
--   * auth.users and auth.uid() / auth.role(), read from request.jwt.claims
--     exactly like PostgREST sets them for each API request
--   * Supabase's default privileges: every new table, view and function in
--     `public` is granted to anon and authenticated. This is why a table
--     without RLS is readable with the public anon key.

do $$ begin
  if not exists (select 1 from pg_roles where rolname = 'anon') then create role anon nologin; end if;
  if not exists (select 1 from pg_roles where rolname = 'authenticated') then create role authenticated nologin; end if;
  if not exists (select 1 from pg_roles where rolname = 'service_role') then create role service_role nologin bypassrls; end if;
end $$;

create schema if not exists auth;
grant usage on schema auth to anon, authenticated, service_role;

create table if not exists auth.users (
  id uuid primary key,
  email text unique not null
);

create or replace function auth.uid() returns uuid
language sql stable as $$
  select nullif(current_setting('request.jwt.claims', true)::json ->> 'sub', '')::uuid
$$;

create or replace function auth.role() returns text
language sql stable as $$
  select coalesce(current_setting('request.jwt.claims', true)::json ->> 'role', 'anon')
$$;

grant usage on schema public to anon, authenticated, service_role;
alter default privileges in schema public grant all on tables to anon, authenticated, service_role;
alter default privileges in schema public grant all on sequences to anon, authenticated, service_role;
alter default privileges in schema public grant execute on functions to anon, authenticated, service_role;
