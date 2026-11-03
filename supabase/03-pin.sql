-- =====================================================================
--  MAVI Streaming+  —  parte 3: PROTEGER LISTA COM PIN
--  Cole TUDO no Supabase › SQL Editor › New query › Run.  (Pode rodar de novo.)
--
--  Lista protegida: no site, servidor/usuário/senha ficam ocultos e editar/remover pede o PIN.
--  No app, usar ou remover a lista pede o PIN.
-- =====================================================================

alter table public.lists add column if not exists pin_hash text;

create or replace function public.mavi_pin_hash(p_id text, p_pin text)
returns text language sql immutable as $$
  select encode(sha256(convert_to(p_id || ':' || p_pin, 'UTF8')), 'hex');
$$;

-- Situação + listas. p_full = true só para o app (precisa dos dados para tocar);
-- para o site, listas protegidas vão sem servidor/usuário/senha.
drop function if exists public.mavi_state(public.devices);
create or replace function public.mavi_state(d public.devices, p_full boolean default false)
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
    'expires_at', case when d.lifetime then null when d.paid_until is not null then d.paid_until else d.trial_until end,
    'lists', coalesce((select jsonb_agg(
        case when l.pin_hash is null or p_full then
          jsonb_build_object('id', l.id, 'name', l.name, 'server', l.server, 'user', l.username, 'pass', l.password,
                             'locked', l.pin_hash is not null, 'pin_hash', case when p_full then l.pin_hash end)
        else
          jsonb_build_object('id', l.id, 'name', l.name, 'locked', true)
        end order by l.updated_at)
       from public.lists l where l.device_id = d.id), '[]'::jsonb)
  );
$$;
revoke all on function public.mavi_state(public.devices, boolean) from public, anon, authenticated;

-- App: registra e recebe tudo (inclusive o PIN cifrado, para conferir no aparelho)
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
  return public.mavi_state(d, true);
end $$;

-- Site: situação + listas (protegidas sem os dados)
create or replace function public.mavi_status(p_mac text, p_key text)
returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare d public.devices;
begin
  d := public.mavi_device(p_mac, p_key);
  if d.id is null then raise exception 'MAC ou Device Key não encontrados'; end if;
  return public.mavi_state(d, false);
end $$;

-- Confere o PIN de uma lista protegida (erro se estiver errado)
create or replace function public.mavi_check_pin(p_device uuid, p_id text, p_pin text)
returns public.lists
language plpgsql stable security definer set search_path = public as $$
declare l public.lists;
begin
  select * into l from public.lists where id = p_id and device_id = p_device;
  if l.id is null then return null; end if;
  if l.pin_hash is not null and l.pin_hash is distinct from public.mavi_pin_hash(l.id, coalesce(p_pin, '')) then
    raise exception 'PIN incorreto';
  end if;
  return l;
end $$;
revoke all on function public.mavi_check_pin(uuid, text, text) from public, anon, authenticated;

-- Site: abre uma lista protegida (com o PIN) para editar
create or replace function public.mavi_list_unlock(p_mac text, p_key text, p_id text, p_pin text)
returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare d public.devices; l public.lists;
begin
  d := public.mavi_device(p_mac, p_key);
  if d.id is null then raise exception 'MAC ou Device Key não encontrados'; end if;
  l := public.mavi_check_pin(d.id, p_id, p_pin);
  if l.id is null then raise exception 'lista não encontrada'; end if;
  return jsonb_build_object('id', l.id, 'name', l.name, 'server', l.server, 'user', l.username, 'pass', l.password,
                            'locked', l.pin_hash is not null);
end $$;

-- Adiciona / altera lista.  Lista protegida: precisa de p_pin.
-- p_new_pin: define/troca o PIN.  p_remove_pin: tira a proteção.
-- Servidor/usuário/senha em branco numa lista existente = mantém os atuais.
drop function if exists public.mavi_list_save(text,text,text,text,text,text,text);
create or replace function public.mavi_list_save(p_mac text, p_key text, p_id text,
  p_name text, p_server text, p_user text, p_pass text,
  p_pin text default null, p_new_pin text default null, p_remove_pin boolean default false)
returns jsonb
language plpgsql volatile security definer set search_path = public as $$
declare d public.devices; l public.lists; v_id text;
begin
  d := public.mavi_device(p_mac, p_key);
  if d.id is null then raise exception 'MAC ou Device Key não encontrados'; end if;
  v_id := coalesce(nullif(trim(p_id),''), gen_random_uuid()::text);
  l := public.mavi_check_pin(d.id, v_id, p_pin);
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

-- Remove lista (protegida: precisa do PIN)
drop function if exists public.mavi_list_delete(text,text,text);
create or replace function public.mavi_list_delete(p_mac text, p_key text, p_id text, p_pin text default null)
returns jsonb
language plpgsql volatile security definer set search_path = public as $$
declare d public.devices; l public.lists;
begin
  d := public.mavi_device(p_mac, p_key);
  if d.id is null then raise exception 'MAC ou Device Key não encontrados'; end if;
  l := public.mavi_check_pin(d.id, p_id, p_pin);
  delete from public.lists where id = p_id and device_id = d.id;
  return public.mavi_state(d, false);
end $$;

-- Funções que já existiam e chamam mavi_state (recriadas para a nova versão)
create or replace function public.mavi_redeem(p_mac text, p_key text, p_code text)
returns jsonb
language plpgsql volatile security definer set search_path = public as $$
declare d public.devices; c public.codes;
begin
  d := public.mavi_device(p_mac, p_key);
  if d.id is null then raise exception 'MAC ou Device Key não encontrados. Abra o app uma vez antes de ativar.'; end if;
  if d.blocked then raise exception 'Aparelho bloqueado'; end if;
  select * into c from public.codes where code = upper(regexp_replace(coalesce(p_code,''), '[^A-Za-z0-9]', '', 'g')) for update;
  if c.code is null then raise exception 'Código inválido'; end if;
  if c.uses >= c.max_uses then raise exception 'Este código já foi usado'; end if;
  if c.valid_until is not null and c.valid_until < now() then raise exception 'Este código expirou'; end if;
  if exists (select 1 from public.code_uses where code = c.code and device_id = d.id) then
    raise exception 'Este código já foi usado neste aparelho';
  end if;
  update public.codes set uses = uses + 1 where code = c.code;
  insert into public.code_uses (code, device_id) values (c.code, d.id);
  d := public.mavi_apply_plan(d.id, c.plan, c.days, 'codigo', c.code);
  return public.mavi_state(d, false);
end $$;

-- Permissões
revoke all on function public.mavi_list_unlock(text,text,text,text),
  public.mavi_list_save(text,text,text,text,text,text,text,text,text,boolean),
  public.mavi_list_delete(text,text,text,text) from public;
grant execute on function public.mavi_register(text,text,text), public.mavi_status(text,text),
  public.mavi_list_unlock(text,text,text,text),
  public.mavi_list_save(text,text,text,text,text,text,text,text,text,boolean),
  public.mavi_list_delete(text,text,text,text), public.mavi_redeem(text,text,text) to anon, authenticated;
