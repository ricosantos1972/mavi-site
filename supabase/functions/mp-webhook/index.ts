// MAVI Streaming+ — recebe as notificações do Mercado Pago e ativa o aparelho
//
// URL (cadastrada automaticamente em cada pagamento pelo mp-checkout e também no painel do MP):
//   https://gzqvyaimzmsbmymvkvme.supabase.co/functions/v1/mp-webhook
//
// Segredos (Supabase › Edge Functions › Secrets):
//   MP_ACCESS_TOKEN    — Access Token da aplicação no Mercado Pago
//   MP_WEBHOOK_SECRET  — "Assinatura secreta" (Suas integrações › aplicação › Webhooks)
//
// Publicar com "Verify JWT" DESLIGADO (quem chama é o Mercado Pago; a segurança é a assinatura x-signature).

const MP_API = 'https://api.mercadopago.com';
const SB_URL = Deno.env.get('SUPABASE_URL')!;
const SB_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
const MP_TOKEN = Deno.env.get('MP_ACCESS_TOKEN') ?? '';
const SECRET = Deno.env.get('MP_WEBHOOK_SECRET') ?? '';

async function hmacHex(secret: string, msg: string) {
  const k = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', k, new TextEncoder().encode(msg));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
// comparação em tempo constante
function safeEqual(a: string, b: string) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

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

Deno.serve(async (req) => {
  if (req.method !== 'POST') return new Response('ok');
  const url = new URL(req.url);
  const body = await req.json().catch(() => ({} as Record<string, any>));
  const type = String(body.type ?? body.topic ?? url.searchParams.get('type') ?? url.searchParams.get('topic') ?? '');
  // o id assinado é o "data.id" da URL (em minúsculas quando tiver letras)
  const dataId = String(url.searchParams.get('data.id') ?? body?.data?.id ?? '').toLowerCase();

  // 1) Assinatura PRIMEIRO
  const signature = req.headers.get('x-signature') ?? '';
  const requestId = req.headers.get('x-request-id') ?? '';
  const parts = Object.fromEntries(signature.split(',').map((p) => p.split('=').map((s) => s.trim())));
  const ts = parts.ts, v1 = parts.v1;
  if (!SECRET || !ts || !v1 || !dataId) return new Response('assinatura ausente', { status: 400 });
  // (sem x-request-id, o trecho "request-id" sai do texto assinado — regra do Mercado Pago)
  const manifest = `id:${dataId};` + (requestId ? `request-id:${requestId};` : '') + `ts:${ts};`;
  const expected = await hmacHex(SECRET, manifest);
  if (!safeEqual(expected, v1)) {
    console.warn('assinatura inválida', { type, dataId });
    return new Response('assinatura inválida', { status: 401 });
  }

  // 2) Só pagamentos interessam (Checkout Pro manda "payment")
  if (type !== 'payment') return new Response('ok');

  // 3) Consulta o pagamento no Mercado Pago (nunca confia no conteúdo da notificação) e grava.
  //    Rápido (1 consulta + 1 gravação) e idempotente: notificações repetidas não ativam duas vezes.
  try {
    const r = await fetch(`${MP_API}/v1/payments/${encodeURIComponent(dataId)}`, { headers: { Authorization: `Bearer ${MP_TOKEN}` } });
    if (!r.ok) {
      console.error('consulta MP falhou', r.status, dataId);
      return new Response('tente depois', { status: 500 });      // o Mercado Pago reenvia
    }
    const p = await r.json();
    if (!p.external_reference) return new Response('ok');          // pagamento de outra origem
    const res = await rpc('mavi_pay_confirm', {
      p_ref: p.external_reference,
      p_mp_id: String(p.id),
      p_status: p.status,
      p_amount: p.transaction_amount,
      p_currency: p.currency_id,
      p_type: p.payment_type_id,
    });
    console.log('pagamento', p.id, p.status, JSON.stringify(res));
    return new Response('ok');
  } catch (e) {
    console.error('erro ao processar', dataId, e);
    return new Response('erro', { status: 500 });                  // o Mercado Pago reenvia
  }
});
