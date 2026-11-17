-- =====================================================================
--  MAVI Streaming+  —  parte 8: versão da GOOGLE PLAY
--  Cole TUDO no Supabase › SQL Editor › New query › Run.  (Pode rodar de novo.)
--
--  Aparelho NOVO que se registra pela versão da Play (app envia versão "x.y.z-play"):
--    • teste grátis de 21 dias (cobre os 14 dias do teste fechado da Play);
--    • já ganha a "Lista demonstração" (mavistreaming.com.br/demo.m3u), para abrir com conteúdo.
--  Versão do site continua com 7 dias e sem lista automática.
-- =====================================================================

create or replace function public.mavi_register(p_mac text, p_key text, p_version text default null)
returns jsonb
language plpgsql volatile security definer set search_path = public as $$
declare d public.devices; v_new boolean; v_play boolean;
begin
  if coalesce(trim(p_mac), '') !~ '^[0-9A-Fa-f:]{17}$' or coalesce(trim(p_key), '') !~ '^[0-9]{6}$' then
    raise exception 'aparelho inválido';
  end if;
  v_new  := not exists (select 1 from public.devices where mac = upper(trim(p_mac)));
  v_play := coalesce(p_version, '') like '%-play';
  insert into public.devices (mac, device_key, app_version, trial_until)
  values (upper(trim(p_mac)), trim(p_key), p_version,
          now() + case when v_play then interval '21 days' else interval '7 days' end)
  on conflict (mac) do update set last_seen = now(), app_version = coalesce(excluded.app_version, devices.app_version)
  where devices.device_key = excluded.device_key
  returning * into d;
  if d.id is null then raise exception 'aparelho inválido'; end if;
  if v_new and v_play then
    insert into public.lists (id, device_id, name, server, username, password, list_type)
    values (gen_random_uuid()::text, d.id, 'Lista demonstração', 'https://mavistreaming.com.br/demo.m3u', '', '', 'm3u')
    on conflict do nothing;
  end if;
  return public.mavi_state(d, true);
end $$;
