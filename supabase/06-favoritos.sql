-- =====================================================================
--  Parte 6: FAVORITOS E "CONTINUAR ASSISTINDO" EM TODOS OS APARELHOS
--  Cole TUDO no Supabase › SQL Editor › New query › Run.  (Pode rodar de novo.)
--
--  Vale para os dois apps. Cada conta (lista) é guardada só por um código
--  embaralhado de 64 letras/números — o banco nunca recebe usuário nem senha.
-- =====================================================================

create table if not exists public.user_sync (
  id          text primary key check (id ~ '^[0-9a-f]{64}$'),
  favs        jsonb not null default '[]'::jsonb,
  pos         jsonb not null default '{}'::jsonb,
  updated_at  timestamptz not null default now()
);
alter table public.user_sync enable row level security;   -- fechada: só pelas funções abaixo
revoke all on public.user_sync from anon, authenticated;

-- Lê. Se p_since for informado e nada mudou desde então, devolve só a data (resposta minúscula).
create or replace function public.sync_get(p_id text, p_since timestamptz default null)
returns jsonb
language sql stable security definer set search_path = public as $$
  select case
    when s.id is null then jsonb_build_object('updated_at', null)
    when p_since is not null and s.updated_at <= p_since then jsonb_build_object('updated_at', s.updated_at)
    else jsonb_build_object('updated_at', s.updated_at, 'favs', s.favs, 'pos', s.pos)
  end
  from (select 1) x left join public.user_sync s on s.id = p_id;
$$;

-- Grava (o app já manda só os mais recentes: 50 canais, 20 filmes, 20 séries, 50 posições).
create or replace function public.sync_put(p_id text, p_favs jsonb, p_pos jsonb)
returns jsonb
language plpgsql volatile security definer set search_path = public as $$
declare v_at timestamptz;
begin
  if p_id !~ '^[0-9a-f]{64}$' then raise exception 'conta inválida'; end if;
  if jsonb_typeof(p_favs) <> 'array' or jsonb_array_length(p_favs) > 100 then raise exception 'favoritos inválidos'; end if;
  if jsonb_typeof(p_pos) <> 'object' or (select count(*) from jsonb_object_keys(p_pos)) > 60 then raise exception 'posições inválidas'; end if;
  if octet_length(p_favs::text) + octet_length(p_pos::text) > 100000 then raise exception 'dados grandes demais'; end if;
  insert into public.user_sync (id, favs, pos, updated_at) values (p_id, p_favs, p_pos, clock_timestamp())
  on conflict (id) do update set favs = excluded.favs, pos = excluded.pos, updated_at = clock_timestamp()
  returning updated_at into v_at;
  return jsonb_build_object('updated_at', v_at);
end $$;

revoke all on function public.sync_get(text, timestamptz) from public;
revoke all on function public.sync_put(text, jsonb, jsonb) from public;
grant execute on function public.sync_get(text, timestamptz) to anon, authenticated;
grant execute on function public.sync_put(text, jsonb, jsonb) to anon, authenticated;
