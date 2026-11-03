-- =====================================================================
--  MAVI Streaming+  —  parte 4: LIMITE DE TENTATIVAS DO PIN
--  Cole TUDO no Supabase › SQL Editor › New query › Run.  (Pode rodar de novo.)
--
--  5 PINs errados seguidos numa lista → bloqueia por 15 minutos.
--  (O erro volta como resposta normal, para a contagem não ser desfeita.)
-- =====================================================================

create table if not exists public.pin_attempts (
  list_id      text primary key references public.lists(id) on delete cascade,
  fails        int not null default 0,
  locked_until timestamptz
);
alter table public.pin_attempts enable row level security;
revoke all on public.pin_attempts from anon, authenticated;

-- Confere o PIN e conta os erros.  Devolve null se OK, ou a mensagem de erro.
drop function if exists public.mavi_check_pin(uuid, text, text);
create or replace function public.mavi_pin_error(p_device uuid, p_id text, p_pin text)
returns text
language plpgsql volatile security definer set search_path = public as $$
declare l public.lists; a public.pin_attempts; v_min int;
begin
  select * into l from public.lists where id = p_id and device_id = p_device;
  if l.id is null or l.pin_hash is null then return null; end if;

  select * into a from public.pin_attempts where list_id = l.id for update;
  if a.locked_until is not null and a.locked_until > now() then
    v_min := ceil(extract(epoch from (a.locked_until - now())) / 60);
    return format('Muitas tentativas erradas. Tente de novo em %s minuto(s).', v_min);
  end if;

  if l.pin_hash = public.mavi_pin_hash(l.id, coalesce(p_pin, '')) then
    delete from public.pin_attempts where list_id = l.id;
    return null;
  end if;

  insert into public.pin_attempts (list_id, fails) values (l.id, 1)
  on conflict (list_id) do update
     set fails = case when pin_attempts.locked_until is not null and pin_attempts.locked_until <= now() then 1
                      else pin_attempts.fails + 1 end,
         locked_until = null
  returning * into a;
  if a.fails >= 5 then
    update public.pin_attempts set fails = 0, locked_until = now() + interval '15 minutes' where list_id = l.id;
    return 'PIN incorreto. Muitas tentativas: lista bloqueada por 15 minutos.';
  end if;
  return format('PIN incorreto (%s de 5 tentativas).', a.fails);
end $$;
revoke all on function public.mavi_pin_error(uuid, text, text) from public, anon, authenticated;

-- Site: abre lista protegida
create or replace function public.mavi_list_unlock(p_mac text, p_key text, p_id text, p_pin text)
returns jsonb
language plpgsql volatile security definer set search_path = public as $$
declare d public.devices; l public.lists; e text;
begin
  d := public.mavi_device(p_mac, p_key);
  if d.id is null then raise exception 'MAC ou Device Key não encontrados'; end if;
  select * into l from public.lists where id = p_id and device_id = d.id;
  if l.id is null then raise exception 'lista não encontrada'; end if;
  e := public.mavi_pin_error(d.id, p_id, p_pin);
  if e is not null then return jsonb_build_object('error', e); end if;
  return jsonb_build_object('id', l.id, 'name', l.name, 'server', l.server, 'user', l.username, 'pass', l.password,
                            'locked', l.pin_hash is not null);
end $$;

-- Adiciona / altera lista
create or replace function public.mavi_list_save(p_mac text, p_key text, p_id text,
  p_name text, p_server text, p_user text, p_pass text,
  p_pin text default null, p_new_pin text default null, p_remove_pin boolean default false)
returns jsonb
language plpgsql volatile security definer set search_path = public as $$
declare d public.devices; l public.lists; v_id text; e text;
begin
  d := public.mavi_device(p_mac, p_key);
  if d.id is null then raise exception 'MAC ou Device Key não encontrados'; end if;
  v_id := coalesce(nullif(trim(p_id),''), gen_random_uuid()::text);
  e := public.mavi_pin_error(d.id, v_id, p_pin);
  if e is not null then return jsonb_build_object('error', e); end if;
  select * into l from public.lists where id = v_id and device_id = d.id;
  if p_new_pin is not null and p_new_pin !~ '^[0-9]{4,6}$' then raise exception 'o PIN deve ter de 4 a 6 números'; end if;

  if l.id is null then
    if coalesce(trim(p_server),'') = '' or coalesce(trim(p_user),'') = '' or coalesce(p_pass,'') = '' then
      raise exception 'preencha servidor, usuário e senha';
    end if;
    if (select count(*) from public.lists where device_id = d.id) >= 20 then raise exception 'limite de 20 listas por aparelho'; end if;
    insert into public.lists (id, device_id, name, server, username, password, pin_hash)
    values (v_id, d.id, coalesce(nullif(trim(p_name),''), 'Minha lista'), trim(p_server), trim(p_user), p_pass,
            case when p_new_pin is not null then public.mavi_pin_hash(v_id, p_new_pin) end);
  else
    update public.lists set
      name = coalesce(nullif(trim(p_name),''), name),
      server = coalesce(nullif(trim(p_server),''), server),
      username = coalesce(nullif(trim(p_user),''), username),
      password = coalesce(nullif(p_pass,''), password),
      pin_hash = case when p_remove_pin then null
                      when p_new_pin is not null then public.mavi_pin_hash(v_id, p_new_pin)
                      else pin_hash end,
      updated_at = now()
    where id = v_id;
  end if;
  select * into d from public.devices where id = d.id;
  return public.mavi_state(d, false);
end $$;

-- Remove lista
create or replace function public.mavi_list_delete(p_mac text, p_key text, p_id text, p_pin text default null)
returns jsonb
language plpgsql volatile security definer set search_path = public as $$
declare d public.devices; e text;
begin
  d := public.mavi_device(p_mac, p_key);
  if d.id is null then raise exception 'MAC ou Device Key não encontrados'; end if;
  e := public.mavi_pin_error(d.id, p_id, p_pin);
  if e is not null then return jsonb_build_object('error', e); end if;
  delete from public.lists where id = p_id and device_id = d.id;
  return public.mavi_state(d, false);
end $$;
