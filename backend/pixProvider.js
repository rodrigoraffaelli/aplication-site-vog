/**
 * pixProvider.js — Adapter de provedor PIX (migração PixVault → brinox)
 *
 * Contrato implementado conforme documentação oficial (doc "brinox"/Resumopay):
 *   AUTH   → HTTP Basic Auth: base64(pk:sk)
 *   CREATE → POST /v1/charge  { amount (R$), external_id, metadata }
 *   RESP   → { id, status, amount, pix: { qr_code, copy_paste }, expires_at }
 *   WEBHOOK→ header X-Resumopay-Signature: sha256=<hmac do corpo com whsec>
 *             header X-Resumopay-Event: charge.paid
 *
 * Trocar de provedor = trocar este arquivo, sem tocar no restante do backend.
 */
const crypto = require('crypto');

// ─── CONFIG: env (fallback) + tabela settings do Supabase (prioridade) ──
// As chaves podem ser preenchidas no painel /admin (POST /api/admin/settings)
// e são gravadas na tabela `settings` — sem redeploy no Render.
const CFG = {
  baseUrl: process.env.BRINOX_BASE_URL || process.env.RESUMOPAY_BASE_URL || 'https://api.brinoxcargo.shop/v1',
  publicKey: process.env.BRINOX_PUBLIC_KEY || process.env.RESUMOPAY_PUBLIC_KEY || '',
  secretKey: process.env.BRINOX_SECRET_KEY || process.env.RESUMOPAY_SECRET_KEY || '',
  webhookSecret: process.env.BRINOX_WEBHOOK_SECRET || process.env.RESUMOPAY_WEBHOOK_SECRET || '',
  timeoutMs: 15000,
};

// Chaves aceitas na tabela `settings` (nome legado genérico + brinox_* + resumopay_*)
const CONFIG_KEYS = {
  baseUrl: ['brinox_base_url', 'base_url', 'resumopay_base_url'],
  publicKey: ['brinox_public_key', 'public_key', 'resumopay_public_key'],
  secretKey: ['brinox_secret_key', 'secret_key', 'resumopay_secret_key'],
  webhookSecret: ['brinox_webhook_secret', 'webhook_secret', 'resumopay_webhook_secret'],
};

function isConfigured() {
  return !!(CFG.publicKey && CFG.secretKey && CFG.baseUrl);
}

/**
 * Carrega a config do provedor da tabela `settings` do Supabase,
 * mesclando com as envs (env vira fallback).
 * Chama no boot do servidor e após salvar no /admin.
 */
async function loadConfig(supabase) {
  const keys = Object.values(CONFIG_KEYS).flat();
  const { data: rows, error } = await supabase
    .from('settings')
    .select('key, value')
    .in('key', keys);

  if (error) {
    console.error('Erro ao carregar config do Supabase:', error.message);
    return null;
  }

  const map = {};
  (rows || []).forEach(r => { map[r.key] = r.value; });

  return {
    baseUrl: map.brinox_base_url || map.base_url || map.resumopay_base_url || CFG.baseUrl,
    publicKey: map.brinox_public_key || map.public_key || map.resumopay_public_key || CFG.publicKey,
    secretKey: map.brinox_secret_key || map.secret_key || map.resumopay_secret_key || CFG.secretKey,
    webhookSecret: map.brinox_webhook_secret || map.webhook_secret || map.resumopay_webhook_secret || CFG.webhookSecret,
  };
}

/**
 * Aplica a config em memória (usada em todas as chamadas ao provedor).
 */
function applyConfig(cfg = {}) {
  if (cfg.baseUrl) CFG.baseUrl = String(cfg.baseUrl).trim();
  if (cfg.publicKey) CFG.publicKey = String(cfg.publicKey).trim();
  if (cfg.secretKey) CFG.secretKey = String(cfg.secretKey).trim();
  if (cfg.webhookSecret) CFG.webhookSecret = String(cfg.webhookSecret).trim();
  return isConfigured();
}

class PixProviderError extends Error {
  constructor(message, { status, providerCode, response } = {}) {
    super(message);
    this.name = 'PixProviderError';
    this.status = status;
    this.providerCode = providerCode;
    this.response = response;
  }
}

// Auth: HTTP Basic Auth com base64(pk:sk) — conforme doc PASSO 1
function authHeaders() {
  const token = Buffer.from(`${CFG.publicKey}:${CFG.secretKey}`).toString('base64');
  return {
    'Content-Type': 'application/json',
    Accept: 'application/json',
    Authorization: `Basic ${token}`,
  };
}

async function request(path, { method = 'GET', body } = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), CFG.timeoutMs);

  let response;
  try {
    response = await fetch(`${CFG.baseUrl}${path}`, {
      method,
      headers: authHeaders(),
      body: body ? JSON.stringify(body) : undefined,
      signal: controller.signal,
    });
  } catch (err) {
    clearTimeout(timeout);
    throw new PixProviderError(`Falha de rede com o provedor: ${err.message}`, { status: 0 });
  }
  clearTimeout(timeout);

  const raw = await response.text();
  let json = null;
  try { json = raw ? JSON.parse(raw) : null; } catch { json = null; }

  if (!response.ok) {
    throw new PixProviderError(
      `Provedor retornou HTTP ${response.status}: ${json?.message || json?.error || raw.slice(0, 200)}`,
      {
        status: response.status,
        providerCode: json?.code || json?.error_code,
        response: json,
      }
    );
  }
  return json;
}

/**
 * Cria uma cobrança PIX dinâmica.
 *
 * @param {object} params
 * @param {number} params.amount     Valor em REAIS (ex.: 198.38)
 * @param {string} params.externalId ID único seu p/ rastrear (session token)
 * @param {object} [params.metadata] Metadados opcionais
 *
 * @returns {Promise<{ providerPaymentId, pixCode, qrCode, status, expiresAt, raw }>}
 */
async function createCharge({ amount, externalId, metadata }) {
  if (!isConfigured()) throw new PixProviderError('Provedor PIX não configurado (envs BRINOX_*)');

  // Doc PASSO 2: POST /v1/charge com amount em REAIS (não centavos!)
  const payload = {
    amount: Number(Number(amount).toFixed(2)),
    external_id: externalId,
    metadata: metadata || { pedido: externalId },
  };

  const json = await request('/charge', { method: 'POST', body: payload });
  return parseCharge(json);
}

// Mapeia a resposta da doc: { id, status, amount, pix: { qr_code, copy_paste }, expires_at }
function parseCharge(json) {
  const root = json?.data || json || {};
  const pix = root.pix || {};

  return {
    providerPaymentId: String(root.id || ''),
    pixCode: String(pix.copy_paste || root.copy_paste || ''),
    qrCode: String(pix.qr_code || root.qr_code || ''),
    status: normalizeStatus(root.status || json.status),
    expiresAt: root.expires_at || null,
    raw: json,
  };
}

/**
 * Consulta status de uma cobrança no provedor.
 *
 * >>> A doc oficial só documenta criação + webhook (sem GET de status).
 *     Este endpoint fica como BEST-EFFORT: se o provedor não expuser
 *     GET /v1/charge/{id}, o polling falha e o status continua vindo
 *     exclusivamente do webhook (comportamento do server.js já cobre isso).
 */
async function getCharge(providerPaymentId) {
  if (!isConfigured()) throw new PixProviderError('Provedor PIX não configurado (envs BRINOX_*)');

  const json = await request(`/charge/${encodeURIComponent(providerPaymentId)}`);
  const root = json?.data || json || {};

  return {
    providerPaymentId: String(root.id || providerPaymentId),
    status: normalizeStatus(root.status || json.status),
    raw: json,
  };
}

/**
 * Verifica assinatura do webhook (doc PASSO 3):
 *   Header: X-Resumopay-Signature: sha256=<hmac-hex do corpo (bruto)>
 *   Header: X-Resumopay-Event: charge.paid | ...
 *   HMAC-SHA256 do corpo com BRINOX_WEBHOOK_SECRET (whsec_...)
 */
function verifyWebhook(req) {
  const rawBody = req.rawBody || Buffer.from(JSON.stringify(req.body));
  const signature =
    req.headers['x-resumopay-signature'] ||
    req.headers['x-brinox-signature'] ||
    req.headers['brinox-signature'] ||
    '';

  if (!signature) {
    throw new PixProviderError('Webhook sem header de assinatura (X-Resumopay-Signature)');
  }

  // Formato esperado: "sha256=<hex>"; aceita também hex puro
  const expected = String(signature).trim().replace(/^sha256=/i, '');
  if (!/^[0-9a-f]{64}$/i.test(expected)) {
    throw new PixProviderError('Formato de assinatura de webhook não reconhecido');
  }

  const computed = crypto
    .createHmac('sha256', CFG.webhookSecret)
    .update(rawBody)
    .digest('hex');

  if (
    computed.length !== expected.length ||
    !crypto.timingSafeEqual(Buffer.from(computed, 'hex'), Buffer.from(expected, 'hex'))
  ) {
    throw new PixProviderError('Assinatura de webhook inválida');
  }

  // Payload da doc: { event, id, status, amount, external_id, metadata }
  const body = req.body || {};

  return {
    providerPaymentId: String(body.id || ''),
    externalId: body.external_id || null,
    status: normalizeStatus(body.status || body.event),
    event: body.event || null,
    amount: body.amount ?? null,
    raw: body,
  };
}

/**
 * Mapeia status do provedor → status interno.
 * Eventos: charge.paid, charge.expired, charge.canceled, etc.
 */
function normalizeStatus(raw) {
  if (!raw) return 'pending';
  const s = String(raw).toUpperCase();

  if (/PAID|PAGO|CONFIRMED|COMPLETED|APPROVED|LIQUIDADO|SUCCEEDED|SUCCESS/.test(s)) return 'paid';
  if (/EXPIRED|EXPIRADO|CANCELED|CANCELLED|CANCELADO|FAILED|FALHOU|REFUNDED|RECHARGED/.test(s)) return 'failed';
  if (/PENDING|WAITING|AGUARDANDO|CREATED|OPEN|PROCESSING|ATIVO|ACTIVE/.test(s)) return 'pending';

  return 'pending';
}

module.exports = {
  CFG,
  CONFIG_KEYS,
  isConfigured,
  loadConfig,
  applyConfig,
  createCharge,
  getCharge,
  verifyWebhook,
  normalizeStatus,
  PixProviderError,
};