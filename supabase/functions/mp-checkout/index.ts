// MAVI Streaming+ — cria o pagamento no Mercado Pago (Checkout Pro: Pix e cartão)
//
// POST { mac, key, plan }            → { init_point }   (o site redireciona o cliente para init_point)
// GET  ?ref=<uuid>&payment_id=<id>   → confere o pagamento direto no Mercado Pago
//                                      (reforço caso a notificação do webhook atrase)
//
// Segredos (Supabase › Edge Functions › Secrets):
//   MP_ACCESS_TOKEN  — Access Token da aplicação no Mercado Pago (NUNCA no site/app)
// Já existem no Supabase: SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY
//
// Publicar com "Verify JWT" DESLIGADO (o site chama sem login; a segurança é a checagem do aparelho no banco).

const SITE = 'https://mavistreaming.com.br';
const MP_API = 'https://api.mercadopago.com';
const SB_URL = Deno.env.get('SUPABASE_URL')!;
const SB_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
const MP_TOKEN = Deno.env.get('MP_ACCESS_TOKEN') ?? '';

const ORIGINS = [SITE, 'https://www.mavistreaming.com.br'];
let CORS: Record<string, string> = {};
const setCors = (req: Request) => {
  const o = req.headers.get('origin') ?? '';
  CORS = {
    'Access-Control-Allow-Origin': ORIGINS.includes(o) ? o : SITE,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'content-type, apikey, authorization, x-client-info',
    'Vary': 'Origin',
  };
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...CORS, 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });

async function rpc(fn: string, args: Record<string, unknown>) {
  const r = await fetch(`${SB_URL}/rest/v1/rpc/${fn}`, {
    method: 'POST',
    headers: { apikey: SB_KEY, Authorization: `Bearer ${SB_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(args),
  });
  const data = await r.json().catch(() => null);
  if (!r.ok) throw new Error(data?.message || `erro ${r.status}`);
  return data;
}

// Consulta o pagamento no Mercado Pago e grava no banco (ativa se aprovado)
async function confirmPayment(paymentId: string) {
  const r = await fetch(`${MP_API}/v1/payments/${encodeURIComponent(paymentId)}`, {
    headers: { Authorization: `Bearer ${MP_TOKEN}` },
  });
  if (!r.ok) throw new Error(`Mercado Pago respondeu ${r.status}`);
  const p = await r.json();
  if (!p.external_reference) return { ok: false, error: 'pagamento sem referência' };
  return await rpc('mavi_pay_confirm', {
    p_ref: p.external_reference,
    p_mp_id: String(p.id),
    p_status: p.status,
    p_amount: p.transaction_amount,
    p_currency: p.currency_id,
    p_type: p.payment_type_id,
  });
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

Deno.serve(async (req) => {
  setCors(req);
  if (req.method === 'OPTIONS') return new Response(null, { headers: CORS });
  if (!MP_TOKEN) return json({ error: 'Pagamento indisponível no momento.' }, 503);

  try {
    // ---- Reforço na volta do checkout: confere o pagamento no Mercado Pago ----
    if (req.method === 'GET') {
      const u = new URL(req.url);
      const ref = u.searchParams.get('ref') ?? '';
      const pid = u.searchParams.get('payment_id') ?? '';
      if (!UUID.test(ref) || !/^\d{1,20}$/.test(pid)) return json({ error: 'parâmetros inválidos' }, 400);
      const res = await confirmPayment(pid);
      const st = await rpc('mavi_pay_status', { p_ref: ref });
      return json({ ...st, checked: res?.ok ?? false });
    }

    if (req.method !== 'POST') return json({ error: 'método não permitido' }, 405);

    // ---- Nova compra ----
    const body = await req.json().catch(() => ({}));
    const mac = String(body.mac ?? '').trim().toUpperCase();
    const key = String(body.key ?? '').trim();
    const plan = String(body.plan ?? '');
    if (!/^([0-9A-F]{2}:){5}[0-9A-F]{2}$/.test(mac) || !/^\d{6}$/.test(key)) {
      return json({ error: 'Informe o MAC e a Device Key (6 números) do app.' }, 400);
    }
    if (!['mensal', 'anual', 'vitalicio'].includes(plan)) return json({ error: 'Plano inválido' }, 400);

    // Banco confere o aparelho e define o preço (o navegador nunca manda valor)
    let start;
    try { start = await rpc('mavi_pay_start', { p_mac: mac, p_key: key, p_plan: plan }); }
    catch (e) { return json({ error: (e as Error).message }, 400); }

    const back = `${SITE}/registrar.html?ref=${start.ref}`;
    const pref = await fetch(`${MP_API}/checkout/preferences`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${MP_TOKEN}`,
        'Content-Type': 'application/json',
        'X-Idempotency-Key': start.ref,
      },
      body: JSON.stringify({
        items: [{
          id: `mavi-${start.plan}`,
          title: start.title,
          description: `Ativação do aplicativo MAVI Streaming+ (aparelho ${start.mac})`,
          category_id: 'services',
          quantity: 1,
          unit_price: Number(start.price),
          currency_id: 'BRL',
        }],
        external_reference: start.ref,
        back_urls: { success: back, failure: back, pending: back },
        auto_return: 'approved',                       // site público em HTTPS
        notification_url: `${SB_URL}/functions/v1/mp-webhook?source_news=webhooks`,
        statement_descriptor: 'MAVISTREAMING',
        payment_methods: {
          excluded_payment_types: [{ id: 'ticket' }, { id: 'atm' }],   // sem boleto/lotérica: só Pix, cartão e saldo MP
          installments: Number(start.installments) || 1,
        },
        expires: true,
        expiration_date_to: new Date(Date.now() + 24 * 3600e3).toISOString(),
        metadata: { plan: start.plan, mac: start.mac },
      }),
    });
    const pj = await pref.json().catch(() => null);
    if (!pref.ok || !pj?.init_point) {
      console.error('preference error', pref.status, JSON.stringify(pj));
      return json({ error: 'Não foi possível iniciar o pagamento. Tente de novo em instantes.' }, 502);
    }
    // ✅ init_point (o checkout de verdade; não existe mais ambiente sandbox)
    return json({ init_point: pj.init_point, ref: start.ref });
  } catch (e) {
    console.error(e);
    return json({ error: 'Erro ao processar. Tente novamente.' }, 500);
  }
});
