-- "ClientHub": a small client portal for an agency, in the shape that
-- AI app builders (Lovable, Bolt, ...) typically generate it.
-- Users sign up, create projects, and see the invoices for their projects.
-- Admins can list all users.
--
-- Every problem in this file is intentional and is a pattern seen in
-- real AI-generated Supabase projects. See AUDIT_REPORT.md for findings.

create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  email text not null,
  full_name text,
  role text not null default 'member' check (role in ('member', 'admin'))
);

create table public.projects (
  id bigint generated always as identity primary key,
  owner_id uuid not null references public.profiles (id) on delete cascade,
  name text not null
);

create table public.invoices (
  id bigint generated always as identity primary key,
  project_id bigint not null references public.projects (id) on delete cascade,
  amount_cents integer not null,
  status text not null default 'open'
);

-- profiles ---------------------------------------------------------------
alter table public.profiles enable row level security;

-- V2: "Profiles are viewable by authenticated users": every user can read
-- every other user's email.
create policy "Profiles are viewable by authenticated users"
  on public.profiles for select to authenticated
  using (true);

-- V3: users may update their own profile, but nothing stops them from
-- updating the `role` column too.
create policy "Users can update own profile"
  on public.profiles for update to authenticated
  using (auth.uid() = id);

-- projects ---------------------------------------------------------------
alter table public.projects enable row level security;

-- V4: "logged in" is treated as "allowed": any user sees all projects.
create policy "Authenticated users can view projects"
  on public.projects for select
  using (auth.role() = 'authenticated');

-- V5: the insert check never compares owner_id with the caller, so a user
-- can create projects in someone else's account.
create policy "Authenticated users can create projects"
  on public.projects for insert
  with check (auth.role() = 'authenticated');

create policy "Owners can update projects"
  on public.projects for update
  using (owner_id = auth.uid());

-- invoices ---------------------------------------------------------------
-- V1: RLS was never enabled. With Supabase's default grants this table is
-- readable (and writable) by anyone holding the public anon key.

-- dashboard view -----------------------------------------------------------
-- V6: a view runs with its owner's rights by default, so it ignores the
-- RLS of the tables underneath. Anyone can read every project's totals.
create view public.project_summaries as
  select p.id, p.name, p.owner_id, pr.email as owner_email,
         count(i.id) as invoice_count,
         coalesce(sum(i.amount_cents), 0) as total_cents
  from public.projects p
  join public.profiles pr on pr.id = p.owner_id
  left join public.invoices i on i.project_id = p.id
  group by p.id, pr.email;

-- admin RPC ----------------------------------------------------------------
-- V7: SECURITY DEFINER bypasses RLS, the function never checks who is
-- calling, and Supabase exposes it as /rest/v1/rpc/admin_list_users to
-- everyone, including anon. The admin screen in the UI is hidden, but the
-- endpoint is not.
create function public.admin_list_users()
returns table (id uuid, email text, role text)
language sql security definer as $$
  select id, email, role from public.profiles
$$;
