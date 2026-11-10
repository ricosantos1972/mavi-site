-- =====================================================================
--  MAVI Streaming+  —  parte 5: LISTA M3U (sem usuário e senha)
--  Cole TUDO no Supabase › SQL Editor › New query › Run.  (Pode rodar de novo.)
--
--  Lista "xtream": servidor + usuário + senha (como antes).
--  Lista "m3u":    server = link da lista; usuário/senha vazios; EPG (XMLTV) opcional.
-- =====================================================================

alter table public.lists add column if not exists list_type text not null default 'xtream';
alter table public.lists add column if not exists epg text;

-- Situação + listas (agora com tipo e EPG)
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
                             'type', l.list_type, 'epg', l.epg,
                             'locked', l.pin_hash is not null, 'pin_hash', case when p_full then l.pin_hash end)
        else
          jsonb_build_object('id', l.id, 'name', l.name, 'type', l.list_type, 'locked', true)
        end order by l.updated_at)
       from public.lists l where l.device_id = d.id), '[]'::jsonb)
  );
$$;
revoke all on function public.mavi_state(public.devices, boolean) from public, anon, authenticated;

-- Site: abre lista protegida (com tipo e EPG)
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
                            'type', l.list_type, 'epg', l.epg, 'locked', l.pin_hash is not null);
end $$;

-- Adiciona / altera lista (com tipo e EPG)
drop function if exists public.mavi_list_save(text,text,text,text,text,text,text,text,text,boolean);
create or replace function public.mavi_list_save(p_mac text, p_key text, p_id text,
  p_name text, p_server text, p_user text, p_pass text,
  p_pin text default null, p_new_pin text default null, p_remove_pin boolean default false,
  p_type text default null, p_epg text default null)
returns jsonb
language plpgsql volatile security definer set search_path = public as $$
declare d public.devices; l public.lists; v_id text; e text; v_type text;
begin
  d := public.mavi_device(p_mac, p_key);
  if d.id is null then raise exception 'MAC ou Device Key não encontrados'; end if;
  v_id := coalesce(nullif(trim(p_id),''), gen_random_uuid()::text);
  e := public.mavi_pin_error(d.id, v_id, p_pin);
  if e is not null then return jsonb_build_object('error', e); end if;
  select * into l from public.lists where id = v_id and device_id = d.id;
  if p_new_pin is not null and p_new_pin !~ '^[0-9]{4,6}$' then raise exception 'o PIN deve ter de 4 a 6 números'; end if;
  v_type := coalesce(nullif(p_type,''), l.list_type, 'xtream');
  if v_type not in ('xtream','m3u') then raise exception 'tipo de lista inválido'; end if;

  if l.id is null then
    if coalesce(trim(p_server),'') = '' then raise exception 'informe o servidor ou o link da lista'; end if;
    if v_type = 'xtream' and (coalesce(trim(p_user),'') = '' or coalesce(p_pass,'') = '') then
      raise exception 'preencha servidor, usuário e senha';
    end if;
    if (select count(*) from public.lists where device_id = d.id) >= 20 then raise exception 'limite de 20 listas por aparelho'; end if;
    insert into public.lists (id, device_id, name, server, username, password, pin_hash, list_type, epg)
    values (v_id, d.id, coalesce(nullif(trim(p_name),''), 'Minha lista'), trim(p_server),
            coalesce(trim(p_user),''), coalesce(p_pass,''),
            case when p_new_pin is not null then public.mavi_pin_hash(v_id, p_new_pin) end,
            v_type, nullif(trim(coalesce(p_epg,'')),''));
  else
    update public.lists set
      name = coalesce(nullif(trim(p_name),''), name),
      server = coalesce(nullif(trim(p_server),''), server),
      username = case when v_type = 'm3u' then '' else coalesce(nullif(trim(p_user),''), username) end,
      password = case when v_type = 'm3u' then '' else coalesce(nullif(p_pass,''), password) end,
      list_type = v_type,
      epg = case when p_epg is null then epg else nullif(trim(p_epg),'') end,
      pin_hash = case when p_remove_pin then null
                      when p_new_pin is not null then public.mavi_pin_hash(v_id, p_new_pin)
                      else pin_hash end,
      updated_at = now()
    where id = v_id;
  end if;
  select * into d from public.devices where id = d.id;
  return public.mavi_state(d, false);
end $$;

revoke all on function public.mavi_list_save(text,text,text,text,text,text,text,text,text,boolean,text,text) from public;
grant execute on function public.mavi_list_save(text,text,text,text,text,text,text,text,text,boolean,text,text) to anon, authenticated;
