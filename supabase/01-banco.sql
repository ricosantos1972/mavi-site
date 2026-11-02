-- =====================================================================
--  MAVI Streaming+  —  banco de dados (Supabase)
--  Cole TUDO no Supabase › SQL Editor › New query › Run.
--  Pode rodar de novo sem problema (não apaga dados).
-- =====================================================================

-- ---------- Tabelas ----------

-- Cada aparelho que abre o app (identificado por MAC + Device Key)
create table if not exists public.devices (
  id            uuid primary key default gen_random_uuid(),
  mac           text not null unique,
  device_key    text not null,
  created_at    timestamptz not null default now(),
  last_seen     timestamptz not null default now(),
  app_version   text,
  trial_until   timestamptz not null default now() + interval '7 days',
  paid_until    timestamptz,                 -- vencimento do plano pago / cortesia
  lifetime      boolean not null default false,
  plan          text not null default 'teste', -- teste | mensal | anual | vitalicio | cortesia
  note          text,                        -- anotação sua (nome do cliente, parceiro...)
  blocked       boolean not null default false
);

-- Listas do cliente (sincronizadas entre app e site)
create table if not exists public.lists (
  id          text primary key,              -- gerado pelo app/site
  device_id   uuid not null references public.devices(id) on delete cascade,
  name        text not null,
  server      text not null,
  username    text not null,
  password    text not null,
  updated_at  timestamptz not null default now()
);
create index if not exists lists_device_idx on public.lists(device_id);

-- Quem pode entrar no painel administrativo do site
create table if not exists public.admins (
  email text primary key
);

-- Histórico de ativações (quem ativou, quando, qual plano)
create table if not exists public.activations (
  id          bigint generated always as identity primary key,
  device_id   uuid not null references public.devices(id) on delete cascade,
  plan        text not null,
  paid_until  timestamptz,
  lifetime    boolean not null default false,
  source      text not null,                 -- admin | play | site
  created_at  timestamptz not null default now(),
  created_by  text
);

-- ---------- Segurança: ninguém lê as tabelas direto ----------
-- O app e o site só usam as funções abaixo.
alter table public.devices     enable row level security;
alter table public.lists       enable row level security;
alter table public.admins      enable row level security;
alter table public.activations enable row level security;
revoke all on public.devices, public.lists, public.admins, public.activations from anon, authenticated;

-- ---------- Funções internas ----------

create or replace function public.mavi_device(p_mac text, p_key text)
returns public.devices
language sql stable security definer set search_path = public as $$
  select * from public.devices
   where mac = upper(trim(p_mac)) and device_key = trim(p_key) limit 1;
$$;
revoke all on function public.mavi_device(text, text) from public, anon, authenticated;

create or replace function public.mavi_state(d public.devices)
returns jsonb
language sql stable security definer set search_path = public as $$
  select jsonb_build_object(
    'status', case
       when d.blocked then 'bloqueado'
       when d.lifetime then 'vitalicio'
       when d.paid_until is not null and d.paid_until > now() then 'ativo'
       when d.trial_until > now() and d.paid_until is null then 'teste'
       else 'vencido' end,
    'plan', d.plan,
    'expires_at', case
       when d.lifetime then null
       when d.paid_until is not null then d.paid_until
       else d.trial_until end,
    'lists', coalesce((select jsonb_agg(jsonb_build_object(
        'id', l.id, 'name', l.name, 'server', l.server,
        'user', l.username, 'pass', l.password) order by l.updated_at)
       from public.lists l where l.device_id = d.id), '[]'::jsonb)
  );
$$;
revoke all on function public.mavi_state(public.devices) from public, anon, authenticated;

-- ---------- Funções do APP e da página "Minhas listas" ----------

-- O app chama ao abrir: cria o aparelho (com 7 dias de teste) na 1ª vez e devolve situação + listas
create or replace function public.mavi_register(p_mac text, p_key text, p_version text default null)
returns jsonb
language plpgsql volatile security definer set search_path = public as $$
declare d public.devices;
begin
  if coalesce(trim(p_mac), '') !~ '^[0-9A-Fa-f:]{17}$' or coalesce(trim(p_key), '') !~ '^[0-9]{6}$' then
    raise exception 'aparelho inválido';
  end if;
  insert into public.devices (mac, device_key, app_version)
  values (upper(trim(p_mac)), trim(p_key), p_version)
  on conflict (mac) do update set last_seen = now(), app_version = coalesce(excluded.app_version, devices.app_version)
  where devices.device_key = excluded.device_key
  returning * into d;
  if d.id is null then raise exception 'aparelho inválido'; end if;
  return public.mavi_state(d);
end $$;

-- Situação + listas (usada pelo site em "Minhas listas")
create or replace function public.mavi_status(p_mac text, p_key text)
returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare d public.devices;
begin
  d := public.mavi_device(p_mac, p_key);
  if d.id is null then raise exception 'MAC ou Device Key não encontrados'; end if;
  return public.mavi_state(d);
end $$;

-- Adiciona ou altera uma lista
create or replace function public.mavi_list_save(p_mac text, p_key text, p_id text,
  p_name text, p_server text, p_user text, p_pass text)
returns jsonb
language plpgsql volatile security definer set search_path = public as $$
declare d public.devices;
begin
  d := public.mavi_device(p_mac, p_key);
  if d.id is null then raise exception 'MAC ou Device Key não encontrados'; end if;
  if coalesce(trim(p_server),'') = '' or coalesce(trim(p_user),'') = '' or coalesce(p_pass,'') = '' then
    raise exception 'preencha servidor, usuário e senha';
  end if;
  if (select count(*) from public.lists where device_id = d.id and id <> p_id) >= 20 then
    raise exception 'limite de 20 listas por aparelho';
  end if;
  insert into public.lists (id, device_id, name, server, username, password)
  values (coalesce(nullif(trim(p_id),''), gen_random_uuid()::text), d.id,
          coalesce(nullif(trim(p_name),''), 'Minha lista'), trim(p_server), trim(p_user), p_pass)
  on conflict (id) do update set name = excluded.name, server = excluded.server,
     username = excluded.username, password = excluded.password, updated_at = now()
  where lists.device_id = d.id;
  return public.mavi_state(d);
end $$;

-- Remove uma lista
create or replace function public.mavi_list_delete(p_mac text, p_key text, p_id text)
returns jsonb
language plpgsql volatile security definer set search_path = public as $$
declare d public.devices;
begin
  d := public.mavi_device(p_mac, p_key);
  if d.id is null then raise exception 'MAC ou Device Key não encontrados'; end if;
  delete from public.lists where id = p_id and device_id = d.id;
  return public.mavi_state(d);
end $$;

-- ---------- Funções do PAINEL ADMIN (só e-mails da tabela admins) ----------

create or replace function public.mavi_is_admin()
returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.admins where lower(email) = lower(coalesce(auth.jwt() ->> 'email', '')));
$$;

create or replace function public.mavi_admin_devices(p_search text default null)
returns setof jsonb
language plpgsql stable security definer set search_path = public as $$
begin
  if not public.mavi_is_admin() then raise exception 'acesso negado'; end if;
  return query
    select jsonb_build_object(
      'mac', d.mac, 'device_key', d.device_key, 'created_at', d.created_at, 'last_seen', d.last_seen,
      'app_version', d.app_version, 'plan', d.plan, 'note', d.note, 'blocked', d.blocked,
      'lists', (select count(*) from public.lists l where l.device_id = d.id))
      || (public.mavi_state(d) - 'lists')
    from public.devices d
    where p_search is null or p_search = ''
       or d.mac ilike '%' || p_search || '%' or d.device_key = p_search or d.note ilike '%' || p_search || '%'
    order by d.last_seen desc
    limit 500;
end $$;

-- Ativa / renova / dá cortesia.  p_plan: mensal | anual | vitalicio | cortesia | teste
-- p_days: dias a somar (mensal=30, anual=365; cortesia = o que você quiser). Ignorado no vitalício.
create or replace function public.mavi_admin_activate(p_mac text, p_plan text, p_days int default null, p_note text default null)
returns jsonb
language plpgsql volatile security definer set search_path = public as $$
declare d public.devices; v_days int; v_base timestamptz;
begin
  if not public.mavi_is_admin() then raise exception 'acesso negado'; end if;
  select * into d from public.devices where mac = upper(trim(p_mac));
  if d.id is null then raise exception 'aparelho não encontrado (o cliente precisa abrir o app uma vez)'; end if;
  if p_plan not in ('mensal','anual','vitalicio','cortesia','teste') then raise exception 'plano inválido'; end if;

  if p_plan = 'vitalicio' then
    update public.devices set lifetime = true, plan = p_plan, blocked = false, note = coalesce(p_note, note)
     where id = d.id returning * into d;
  else
    v_days := coalesce(p_days, case p_plan when 'mensal' then 30 when 'anual' then 365 else 7 end);
    v_base := greatest(now(), coalesce(d.paid_until, now()), case when d.paid_until is null then d.trial_until else now() end);
    update public.devices
       set paid_until = v_base + make_interval(days => v_days),
           lifetime = false, plan = p_plan, blocked = false, note = coalesce(p_note, note)
     where id = d.id returning * into d;
  end if;

  insert into public.activations (device_id, plan, paid_until, lifetime, source, created_by)
  values (d.id, p_plan, d.paid_until, d.lifetime, 'admin', auth.jwt() ->> 'email');
  return public.mavi_state(d) - 'lists';
end $$;

-- Bloqueia / desbloqueia / zera a ativação
create or replace function public.mavi_admin_set(p_mac text, p_blocked boolean default null,
  p_note text default null, p_reset boolean default false)
returns jsonb
language plpgsql volatile security definer set search_path = public as $$
declare d public.devices;
begin
  if not public.mavi_is_admin() then raise exception 'acesso negado'; end if;
  update public.devices
     set blocked = coalesce(p_blocked, blocked),
         note = coalesce(p_note, note),
         paid_until = case when p_reset then null else paid_until end,
         lifetime = case when p_reset then false else lifetime end,
         plan = case when p_reset then 'teste' else plan end
   where mac = upper(trim(p_mac)) returning * into d;
  if d.id is null then raise exception 'aparelho não encontrado'; end if;
  return public.mavi_state(d) - 'lists';
end $$;

-- ---------- Permissões das funções ----------
revoke all on function public.mavi_register(text,text,text), public.mavi_status(text,text),
  public.mavi_list_save(text,text,text,text,text,text,text), public.mavi_list_delete(text,text,text),
  public.mavi_is_admin(), public.mavi_admin_devices(text), public.mavi_admin_activate(text,text,int,text),
  public.mavi_admin_set(text,boolean,text,boolean) from public;

grant execute on function public.mavi_register(text,text,text), public.mavi_status(text,text),
  public.mavi_list_save(text,text,text,text,text,text,text), public.mavi_list_delete(text,text,text)
  to anon, authenticated;
grant execute on function public.mavi_is_admin(), public.mavi_admin_devices(text),
  public.mavi_admin_activate(text,text,int,text), public.mavi_admin_set(text,boolean,text,boolean)
  to authenticated;

-- ---------- Seu acesso de administrador ----------
insert into public.admins (email) values ('riicardo.santos@terra.com.br') on conflict do nothing;
