-- =====================================================================
--  MAVI Streaming+  —  parte 2: CÓDIGOS DE ATIVAÇÃO
--  Cole TUDO no Supabase › SQL Editor › New query › Run.  (Pode rodar de novo.)
--
--  Você gera os códigos no painel (admin.html) e entrega ao cliente / parceiro.
--  O cliente ativa em mavistreaming.com.br/registrar com MAC + Device Key + código.
--  Depois, o pagamento online (Mercado Pago) vai usar a mesma função de ativação.
-- =====================================================================

create table if not exists public.codes (
  code        text primary key,
  plan        text not null,                 -- mensal | anual | vitalicio | cortesia
  days        int,                           -- dias que o código dá (ignorado no vitalício)
  max_uses    int not null default 1,
  uses        int not null default 0,
  note        text,                          -- p/ quem foi (cliente, parceiro, promoção...)
  created_at  timestamptz not null default now(),
  valid_until timestamptz,                   -- até quando o código pode ser usado (opcional)
  created_by  text
);
create table if not exists public.code_uses (
  id         bigint generated always as identity primary key,
  code       text not null references public.codes(code) on delete cascade,
  device_id  uuid not null references public.devices(id) on delete cascade,
  used_at    timestamptz not null default now()
);
alter table public.codes enable row level security;
alter table public.code_uses enable row level security;
revoke all on public.codes, public.code_uses from anon, authenticated;

-- Aplica um plano a um aparelho (usada pelo código, pelo painel e, no futuro, pelo pagamento)
create or replace function public.mavi_apply_plan(p_device uuid, p_plan text, p_days int, p_source text, p_by text)
returns public.devices
language plpgsql volatile security definer set search_path = public as $$
declare d public.devices; v_days int; v_base timestamptz;
begin
  select * into d from public.devices where id = p_device for update;
  if p_plan = 'vitalicio' then
    update public.devices set lifetime = true, plan = p_plan, blocked = false where id = d.id returning * into d;
  else
    v_days := coalesce(p_days, case p_plan when 'mensal' then 30 when 'anual' then 365 else 30 end);
    v_base := greatest(now(), coalesce(d.paid_until, now()), case when d.paid_until is null then d.trial_until else now() end);
    update public.devices set paid_until = v_base + make_interval(days => v_days),
           lifetime = false, plan = p_plan, blocked = false
     where id = d.id returning * into d;
  end if;
  insert into public.activations (device_id, plan, paid_until, lifetime, source, created_by)
  values (d.id, p_plan, d.paid_until, d.lifetime, p_source, p_by);
  return d;
end $$;
revoke all on function public.mavi_apply_plan(uuid,text,int,text,text) from public, anon, authenticated;

-- Cliente: ativa com um código
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
  return public.mavi_state(d);
end $$;

-- Painel: gera códigos
create or replace function public.mavi_admin_create_codes(p_plan text, p_days int default null,
  p_qty int default 1, p_max_uses int default 1, p_note text default null, p_valid_days int default null)
returns setof text
language plpgsql volatile security definer set search_path = public as $$
declare i int; v text;
begin
  if not public.mavi_is_admin() then raise exception 'acesso negado'; end if;
  if p_plan not in ('mensal','anual','vitalicio','cortesia') then raise exception 'plano inválido'; end if;
  if p_qty < 1 or p_qty > 200 then raise exception 'quantidade de 1 a 200'; end if;
  for i in 1..p_qty loop
    loop
      -- 12 caracteres sem letras/números que confundem (0/O, 1/I/L)
      v := (select string_agg(substr('ABCDEFGHJKMNPQRSTUVWXYZ23456789', 1 + floor(random() * 31)::int, 1), '')
              from generate_series(1, 12));
      exit when not exists (select 1 from public.codes where code = v);
    end loop;
    insert into public.codes (code, plan, days, max_uses, note, valid_until, created_by)
    values (v, p_plan, case when p_plan = 'vitalicio' then null else p_days end, greatest(p_max_uses, 1), p_note,
            case when p_valid_days is null then null else now() + make_interval(days => p_valid_days) end,
            auth.jwt() ->> 'email');
    return next v;
  end loop;
end $$;

-- Painel: lista os códigos
create or replace function public.mavi_admin_codes()
returns setof jsonb
language plpgsql stable security definer set search_path = public as $$
begin
  if not public.mavi_is_admin() then raise exception 'acesso negado'; end if;
  return query select to_jsonb(c) from public.codes c order by c.created_at desc limit 500;
end $$;

-- Painel: apaga um código
create or replace function public.mavi_admin_delete_code(p_code text)
returns void
language plpgsql volatile security definer set search_path = public as $$
begin
  if not public.mavi_is_admin() then raise exception 'acesso negado'; end if;
  delete from public.codes where code = p_code;
end $$;

-- O painel passa a usar a mesma função de ativação (mesmas regras)
create or replace function public.mavi_admin_activate(p_mac text, p_plan text, p_days int default null, p_note text default null)
returns jsonb
language plpgsql volatile security definer set search_path = public as $$
declare d public.devices;
begin
  if not public.mavi_is_admin() then raise exception 'acesso negado'; end if;
  select * into d from public.devices where mac = upper(trim(p_mac));
  if d.id is null then raise exception 'aparelho não encontrado (o cliente precisa abrir o app uma vez)'; end if;
  if p_plan not in ('mensal','anual','vitalicio','cortesia','teste') then raise exception 'plano inválido'; end if;
  d := public.mavi_apply_plan(d.id, p_plan, p_days, 'admin', auth.jwt() ->> 'email');
  if p_note is not null then update public.devices set note = p_note where id = d.id returning * into d; end if;
  return public.mavi_state(d) - 'lists';
end $$;

-- Permissões
revoke all on function public.mavi_redeem(text,text,text),
  public.mavi_admin_create_codes(text,int,int,int,text,int), public.mavi_admin_codes(),
  public.mavi_admin_delete_code(text) from public, anon;
grant execute on function public.mavi_redeem(text,text,text) to anon, authenticated;
grant execute on function public.mavi_admin_create_codes(text,int,int,int,text,int), public.mavi_admin_codes(),
  public.mavi_admin_delete_code(text) to authenticated;
-- Funções de admin não precisam ficar visíveis para visitantes
revoke execute on function public.mavi_admin_devices(text), public.mavi_admin_activate(text,text,int,text),
  public.mavi_admin_set(text,boolean,text,boolean) from anon;
