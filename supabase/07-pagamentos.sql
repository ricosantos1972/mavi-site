-- =====================================================================
--  MAVI Streaming+  —  07: pagamento online (Mercado Pago, Checkout Pro)
--  Cole TUDO no Supabase › SQL Editor › New query › Run.
--  Pode rodar de novo sem problema (não apaga dados).
--
--  Quem chama estas funções são as Edge Functions mp-checkout e mp-webhook
--  (com a chave service_role, que fica só no servidor). O site só consulta
--  a situação de um pagamento pelo código dele (mavi_pay_status).
-- =====================================================================

-- Preços oficiais (o valor cobrado sai SEMPRE daqui, nunca do navegador)
create table if not exists public.plan_prices (
  plan          text primary key,              -- mensal | anual | vitalicio
  title         text not null,
  price         numeric(10,2) not null check (price > 0),
  days          int,                           -- null = vitalício
  installments  int not null default 1,        -- parcelas máximas no cartão
  active        boolean not null default true
);
insert into public.plan_prices (plan, title, price, days, installments) values
  ('mensal',    'MAVI Streaming+ — Plano Mensal (30 dias)',  10.50,  30,  1),
  ('anual',     'MAVI Streaming+ — Plano Anual (365 dias)',  35.00, 365,  3),
  ('vitalicio', 'MAVI Streaming+ — Plano Vitalício',        300.00, null, 12)
on conflict (plan) do update set title = excluded.title, price = excluded.price,
  days = excluded.days, installments = excluded.installments;

-- Cada tentativa de compra
create table if not exists public.payments (
  ref            uuid primary key default gen_random_uuid(),   -- external_reference no Mercado Pago
  device_id      uuid not null references public.devices(id) on delete cascade,
  plan           text not null references public.plan_prices(plan),
  amount         numeric(10,2) not null,
  status         text not null default 'criado',  -- criado | pending | approved | rejected | cancelled | refunded | charged_back | in_process
  mp_payment_id  text unique,
  payment_type   text,                            -- pix (bank_transfer) | credit_card | ...
  applied        boolean not null default false,  -- plano já aplicado (evita aplicar duas vezes)
  created_at     timestamptz not null default now(),
  updated_at     timestamptz not null default now(),
  approved_at    timestamptz
);
create index if not exists payments_device_idx on public.payments(device_id);

alter table public.plan_prices enable row level security;
alter table public.payments    enable row level security;
revoke all on public.plan_prices, public.payments from anon, authenticated;

-- Preços para a vitrine do site (só leitura)
create or replace function public.mavi_prices()
returns jsonb
language sql stable security definer set search_path = public as $$
  select coalesce(jsonb_agg(jsonb_build_object('plan', plan, 'price', price, 'days', days, 'installments', installments)
                            order by price), '[]'::jsonb)
  from public.plan_prices where active;
$$;
grant execute on function public.mavi_prices() to anon, authenticated;

-- Servidor (mp-checkout): confere o aparelho e registra a compra. Devolve o que vai para o Mercado Pago.
create or replace function public.mavi_pay_start(p_mac text, p_key text, p_plan text)
returns jsonb
language plpgsql volatile security definer set search_path = public as $$
declare d public.devices; p public.plan_prices; v_ref uuid;
begin
  d := public.mavi_device(p_mac, p_key);
  if d.id is null then raise exception 'MAC ou Device Key não encontrados. Abra o app uma vez antes de comprar.'; end if;
  if d.blocked then raise exception 'Aparelho bloqueado. Fale com o suporte.'; end if;
  if d.lifetime then raise exception 'Este aparelho já tem o plano vitalício.'; end if;
  select * into p from public.plan_prices where plan = p_plan and active;
  if p.plan is null then raise exception 'Plano inválido'; end if;
  insert into public.payments (device_id, plan, amount) values (d.id, p.plan, p.price) returning ref into v_ref;
  return jsonb_build_object('ref', v_ref, 'plan', p.plan, 'title', p.title, 'price', p.price,
                            'installments', p.installments, 'mac', d.mac);
end $$;
revoke all on function public.mavi_pay_start(text,text,text) from public, anon, authenticated;
grant execute on function public.mavi_pay_start(text,text,text) to service_role;

-- Servidor (mp-webhook / verificação): grava o pagamento consultado NO Mercado Pago e ativa se aprovado.
-- Só ativa se: aprovado + moeda BRL + valor pago >= preço + ainda não aplicado.
create or replace function public.mavi_pay_confirm(p_ref uuid, p_mp_id text, p_status text,
                                                   p_amount numeric, p_currency text, p_type text)
returns jsonb
language plpgsql volatile security definer set search_path = public as $$
declare pay public.payments; d public.devices; p public.plan_prices;
begin
  select * into pay from public.payments where ref = p_ref for update;
  if pay.ref is null then return jsonb_build_object('ok', false, 'error', 'ref desconhecida'); end if;
  -- um mesmo ref só aceita um pagamento aprovado
  if pay.applied and pay.mp_payment_id is distinct from p_mp_id then
    return jsonb_build_object('ok', true, 'ignored', 'ref já paga por outro pagamento');
  end if;

  update public.payments set status = p_status, mp_payment_id = coalesce(mp_payment_id, p_mp_id),
         payment_type = coalesce(p_type, payment_type), updated_at = now()
   where ref = pay.ref returning * into pay;

  if p_status = 'approved' and not pay.applied then
    select * into p from public.plan_prices where plan = pay.plan;
    if p_currency <> 'BRL' or p_amount < pay.amount then
      update public.payments set status = 'valor_divergente' where ref = pay.ref;
      return jsonb_build_object('ok', false, 'error', 'valor ou moeda divergente');
    end if;
    d := public.mavi_apply_plan(pay.device_id, pay.plan, p.days, 'mercadopago', p_mp_id);
    update public.payments set applied = true, approved_at = now() where ref = pay.ref;
    return jsonb_build_object('ok', true, 'activated', true);
  end if;
  return jsonb_build_object('ok', true, 'status', p_status);
end $$;
revoke all on function public.mavi_pay_confirm(uuid,text,text,numeric,text,text) from public, anon, authenticated;
grant execute on function public.mavi_pay_confirm(uuid,text,text,numeric,text,text) to service_role;

-- Site: situação de uma compra pelo código (o ref é um UUID impossível de adivinhar)
create or replace function public.mavi_pay_status(p_ref uuid)
returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare pay public.payments; d public.devices; st jsonb;
begin
  select * into pay from public.payments where ref = p_ref;
  if pay.ref is null then raise exception 'Pagamento não encontrado'; end if;
  select * into d from public.devices where id = pay.device_id;
  st := public.mavi_state(d, false);
  return jsonb_build_object('status', pay.status, 'applied', pay.applied, 'plan', pay.plan, 'amount', pay.amount,
                            'device', jsonb_build_object('status', st->'status', 'expires_at', st->'expires_at'));
end $$;
grant execute on function public.mavi_pay_status(uuid) to anon, authenticated;

-- Painel: últimos pagamentos
create or replace function public.mavi_admin_payments(p_limit int default 100)
returns jsonb
language plpgsql stable security definer set search_path = public as $$
begin
  if not public.mavi_is_admin() then raise exception 'sem permissão'; end if;
  return coalesce((select jsonb_agg(x order by x.created_at desc) from (
    select p.created_at, p.approved_at, p.plan, p.amount, p.status, p.payment_type, p.mp_payment_id, p.applied,
           d.mac, d.note
      from public.payments p join public.devices d on d.id = p.device_id
     where p.status <> 'criado' or p.created_at > now() - interval '1 day'
     order by p.created_at desc limit greatest(1, least(p_limit, 500))) x), '[]'::jsonb);
end $$;
grant execute on function public.mavi_admin_payments(int) to authenticated;

-- Painel: mudar preço (pelo SQL Editor use: update plan_prices set price = 12.90 where plan = 'mensal';)
create or replace function public.mavi_admin_set_price(p_plan text, p_price numeric)
returns jsonb
language plpgsql volatile security definer set search_path = public as $$
begin
  if not public.mavi_is_admin() then raise exception 'sem permissão'; end if;
  update public.plan_prices set price = p_price where plan = p_plan;
  return public.mavi_prices();
end $$;
grant execute on function public.mavi_admin_set_price(text, numeric) to authenticated;
