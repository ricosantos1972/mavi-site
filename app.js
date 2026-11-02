// MAVI Streaming+ — acesso ao banco (Supabase). A chave "publishable" é pública por natureza:
// as tabelas ficam fechadas e só as funções do banco podem ser chamadas.
const SUPABASE_URL = 'https://gzqvyaimzmsbmymvkvme.supabase.co';
const SUPABASE_KEY = 'sb_publishable_KcNv7UQK29mWHvVryYH4Ug_npI_kIVn';

async function rpc(fn, args, token) {
  const r = await fetch(`${SUPABASE_URL}/rest/v1/rpc/${fn}`, {
    method: 'POST',
    headers: {
      'apikey': SUPABASE_KEY,
      'Authorization': `Bearer ${token || SUPABASE_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(args || {}),
  });
  const txt = await r.text();
  let data = null;
  try { data = txt ? JSON.parse(txt) : null; } catch (_) { data = txt; }
  if (!r.ok) throw new Error((data && (data.message || data.msg)) || `Erro ${r.status}`);
  return data;
}

async function signIn(email, password) {
  const r = await fetch(`${SUPABASE_URL}/auth/v1/token?grant_type=password`, {
    method: 'POST',
    headers: { 'apikey': SUPABASE_KEY, 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  const d = await r.json();
  if (!r.ok) throw new Error(d.error_description || d.msg || 'E-mail ou senha incorretos');
  return d; // { access_token, expires_in, user }
}

function fmtDate(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  return d.toLocaleDateString('pt-BR');
}

function statusText(st) {
  switch (st.status) {
    case 'vitalicio': return 'Aplicativo Ativado - vitalício';
    case 'ativo': return `Aplicativo Ativado - vence em ${fmtDate(st.expires_at)}`;
    case 'teste': return `Teste grátis - vence em ${fmtDate(st.expires_at)}`;
    case 'bloqueado': return 'Aparelho bloqueado';
    default: return `Ativação vencida${st.expires_at ? ' em ' + fmtDate(st.expires_at) : ''}`;
  }
}

function dotClass(st) {
  return st === 'ativo' || st === 'vitalicio' ? '' : st === 'teste' ? 'warn' : 'bad';
}

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// Link M3U do painel (get.php?username=...&password=...) → servidor, usuário e senha
function parseM3u(link) {
  try {
    const u = new URL(/^https?:\/\//i.test(link) ? link : 'http://' + link);
    const user = u.searchParams.get('username'), pass = u.searchParams.get('password');
    if (!user || !pass) return null;
    return { server: `${u.protocol}//${u.host}`, user, pass };
  } catch (_) { return null; }
}

function normMac(s) {
  const hex = String(s || '').toUpperCase().replace(/[^0-9A-F]/g, '');
  return hex.length === 12 ? hex.match(/.{2}/g).join(':') : String(s || '').trim().toUpperCase();
}
