create table profiles (
  id uuid primary key references auth.users on delete cascade,
  name text,
  timezone text not null default 'Africa/Lagos',
  role text not null default 'tutor' check (role in ('tutor','admin')),
  onboarded boolean not null default false,
  created_at timestamptz default now()
);

create table classes (
  id uuid primary key default gen_random_uuid(),
  tutor_id uuid not null references profiles on delete cascade,
  title text not null,
  subject text not null,
  max_students int,
  created_at timestamptz default now()
);

-- weekday: 0 = Sunday ... 6 = Saturday
create table class_sessions (
  id uuid primary key default gen_random_uuid(),
  class_id uuid not null references classes on delete cascade,
  weekday smallint not null check (weekday between 0 and 6),
  start_time time not null,
  end_time time not null check (end_time > start_time)
);

create table students (
  id uuid primary key default gen_random_uuid(),
  tutor_id uuid not null references profiles on delete cascade,
  name text not null,
  contact text
);

create table enrollments (
  class_id uuid references classes on delete cascade,
  student_id uuid references students on delete cascade,
  primary key (class_id, student_id)
);

create table blocked_times (
  id uuid primary key default gen_random_uuid(),
  tutor_id uuid not null references profiles on delete cascade,
  weekday smallint not null check (weekday between 0 and 6),
  start_time time not null,
  end_time time not null check (end_time > start_time),
  label text
);

create table calendar_connections (
  tutor_id uuid primary key references profiles on delete cascade,
  google_refresh_token text not null, -- encrypt at rest (e.g. Supabase Vault) before production
  calendar_id text default 'primary'
);

-- Auto-create a profile on signup
create function handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into profiles (id, name) values (new.id, new.raw_user_meta_data->>'name');
  return new;
end $$;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function handle_new_user();

-- Row-level security: tutors only touch their own rows
alter table profiles enable row level security;
alter table classes enable row level security;
alter table class_sessions enable row level security;
alter table students enable row level security;
alter table enrollments enable row level security;
alter table blocked_times enable row level security;
alter table calendar_connections enable row level security;

create policy own_profile on profiles for all using (id = auth.uid()) with check (id = auth.uid());
-- role is changed by admins via SQL/service key only, never by the client
revoke update (role) on profiles from authenticated;

create policy own_classes on classes for all using (tutor_id = auth.uid()) with check (tutor_id = auth.uid());
create policy own_students on students for all using (tutor_id = auth.uid()) with check (tutor_id = auth.uid());
create policy own_blocked on blocked_times for all using (tutor_id = auth.uid()) with check (tutor_id = auth.uid());
create policy own_calendar on calendar_connections for all using (tutor_id = auth.uid()) with check (tutor_id = auth.uid());
create policy own_sessions on class_sessions for all
  using (exists (select 1 from classes c where c.id = class_id and c.tutor_id = auth.uid()))
  with check (exists (select 1 from classes c where c.id = class_id and c.tutor_id = auth.uid()));
create policy own_enrollments on enrollments for all
  using (exists (select 1 from classes c where c.id = class_id and c.tutor_id = auth.uid()))
  with check (exists (select 1 from classes c where c.id = class_id and c.tutor_id = auth.uid()));

-- To make an admin: set app_metadata {"role":"admin"} on that auth user
-- (the API guard reads it from the JWT) and update profiles.role to match.