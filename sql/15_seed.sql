-- Demo data, inserted as the database owner (bypasses RLS).
insert into auth.users (id, email) values
  ('11111111-1111-1111-1111-111111111111', 'alice@example.com'),
  ('22222222-2222-2222-2222-222222222222', 'bob@example.com'),
  ('33333333-3333-3333-3333-333333333333', 'carol@example.com');

insert into public.profiles (id, email, full_name, role) values
  ('11111111-1111-1111-1111-111111111111', 'alice@example.com', 'Alice', 'member'),
  ('22222222-2222-2222-2222-222222222222', 'bob@example.com', 'Bob', 'member'),
  ('33333333-3333-3333-3333-333333333333', 'carol@example.com', 'Carol', 'admin');

insert into public.projects (owner_id, name) values
  ('11111111-1111-1111-1111-111111111111', 'Alice website redesign'),
  ('22222222-2222-2222-2222-222222222222', 'Bob mobile app');

insert into public.invoices (project_id, amount_cents, status) values
  (1, 120000, 'paid'), (1, 80000, 'open'),
  (2, 450000, 'open');
