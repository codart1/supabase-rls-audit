-- Fix migration for ClientHub. Apply on top of the existing schema
-- (e.g. supabase/migrations/<timestamp>_rls_hardening.sql).
-- Each block names the finding it closes; see AUDIT_REPORT.md.

-- V1: invoices had no RLS. Owners of the parent project may read them.
-- Writes are left to the server (service_role / Stripe webhook), so no
-- insert/update/delete policy is created for end users.
alter table public.invoices enable row level security;

create policy "Project owners can view their invoices"
  on public.invoices for select to authenticated
  using (exists (
    select 1 from public.projects p
    where p.id = invoices.project_id and p.owner_id = (select auth.uid())
  ));

revoke all on public.invoices from anon;
revoke insert, update, delete, truncate on public.invoices from authenticated;

-- V2: users read only their own profile.
drop policy "Profiles are viewable by authenticated users" on public.profiles;
create policy "Users can view own profile"
  on public.profiles for select to authenticated
  using ((select auth.uid()) = id);

-- V3: users may change their name, never their role or email.
-- Column-level privileges are enforced before RLS is even evaluated.
drop policy "Users can update own profile" on public.profiles;
create policy "Users can update own profile"
  on public.profiles for update to authenticated
  using ((select auth.uid()) = id)
  with check ((select auth.uid()) = id);
revoke update on public.profiles from anon, authenticated;
grant update (full_name) on public.profiles to authenticated;
revoke all on public.profiles from anon;

-- Helper used by the admin checks below. SECURITY DEFINER so that it can
-- read profiles.role without being blocked by the select policy above;
-- it only ever answers about the caller.
create function public.is_admin()
returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (
    select 1 from public.profiles
    where id = (select auth.uid()) and role = 'admin'
  )
$$;
revoke execute on function public.is_admin() from public, anon;

-- V4: users see only their own projects.
drop policy "Authenticated users can view projects" on public.projects;
create policy "Owners can view projects"
  on public.projects for select to authenticated
  using (owner_id = (select auth.uid()));

-- V5: new projects must belong to the caller.
drop policy "Authenticated users can create projects" on public.projects;
create policy "Users can create own projects"
  on public.projects for insert to authenticated
  with check (owner_id = (select auth.uid()));

drop policy "Owners can update projects" on public.projects;
create policy "Owners can update projects"
  on public.projects for update to authenticated
  using (owner_id = (select auth.uid()))
  with check (owner_id = (select auth.uid()));
revoke all on public.projects from anon;

-- V6: the view now runs with the caller's rights (Postgres 15+), so the
-- table policies above apply to it, and anon loses access.
alter view public.project_summaries set (security_invoker = true);
revoke all on public.project_summaries from anon;

-- V7: check the caller inside the function, pin search_path, and stop
-- exposing it to anon.
create or replace function public.admin_list_users()
returns table (id uuid, email text, role text)
language plpgsql security definer set search_path = '' as $$
begin
  if not public.is_admin() then
    raise exception 'not allowed' using errcode = '42501';
  end if;
  return query select p.id, p.email, p.role from public.profiles p;
end
$$;
revoke execute on function public.admin_list_users() from public, anon;
grant execute on function public.admin_list_users() to authenticated;
