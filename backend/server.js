console.log('### VERSAO PIX-BRINOX 2026-08-22 ###');
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const crypto = require('crypto');
const path = require('path');

const pixProvider = require('./pixProvider');

const app = express();
const upload = multer({ dest: 'uploads/' });

// ─── CONFIG ──────────────────────────────────────────────
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;
// service_role ignora RLS e NUNCA deve ir pro frontend.
// Com ele, as tabelas sensíveis (settings, admins, cpf_api_keys, receipts)
// podem ter RLS ligado sem quebrar o backend.
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || SUPABASE_ANON_KEY;
const JWT_SECRET = process.env.JWT_SECRET || 'secret_change_me';
const PORT = process.env.PORT || 3001;

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

app.use(cors());
// rawBody é necessário para verificar a assinatura do webhook
app.use(express.json({ verify: (req, res, buf) => { req.rawBody = buf; } }));

// ─── MIDDLEWARE: VERIFICAR TOKEN ADMIN ──────────────────
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Não autorizado' });
  }
  const token = authHeader.split(' ')[1];
  try {
    req.admin = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Token inválido' });
  }
}

// ─── NORMALIZAÇÃO DE DATA ───────────────────────────────
/**
 * Converte QUALQUER formato comum de data para YYYY-MM-DD:
 *   DD/MM/YYYY, DD-MM-YYYY, YYYY-MM-DD, YYYY/MM/DD,
 *   ISO com hora (1995-08-10T00:00:00.000Z), timestamp.
 *
 * Nunca retorna null/undefined: se não conseguir converter,
 * retorna '' (string vazia) para o frontend NÃO quebrar
 * (null.split() causa tela branca no React).
 */
function normalizarData(data) {
  if (data === null || data === undefined) return '';
  const valor = String(data).trim();
  if (!valor) return '';

  // Já está em YYYY-MM-DD
  if (/^\d{4}-\d{2}-\d{2}$/.test(valor)) return valor;

  // YYYY/MM/DD
  if (/^\d{4}\/\d{2}\/\d{2}$/.test(valor)) {
    const [ano, mes, dia] = valor.split('/');
    return `${ano}-${mes}-${dia}`;
  }

  // ISO com hora: 1995-08-10T00:00:00.000Z ou "1995-08-10 00:00:00"
  if (/^\d{4}-\d{2}-\d{2}/.test(valor)) {
    return valor.slice(0, 10);
  }

  // DD/MM/YYYY (com ou sem hora)
  let m = valor.match(/^(\d{2})\/(\d{2})\/(\d{4})/);
  if (m) return `${m[3]}-${m[2]}-${m[1]}`;

  // DD-MM-YYYY
  m = valor.match(/^(\d{2})-(\d{2})-(\d{4})/);
  if (m) return `${m[3]}-${m[2]}-${m[1]}`;

  // Timestamp (segundos ou milissegundos)
  if (/^\d{9,13}$/.test(valor)) {
    const t = Number(valor);
    const dt = new Date(t > 1e12 ? t : t * 1000);
    if (!isNaN(dt.getTime())) return dt.toISOString().slice(0, 10);
  }

  console.warn('Formato de data não reconhecido:', valor);
  return '';
}

// ─── CONSULTA API EXTERNA DE CPF ────────────────────────
async function fetchCpfFromApi(cpf) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);

  try {
    const response = await fetch(process.env.CONSULTA_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ module: 'cpf', query: cpf }),
      signal: controller.signal
    });

    if (!response.ok) {
      console.error('CONSULTA_URL retornou HTTP:', response.status);
      return null;
    }

    const json = await response.json();
    const dados = json?.data?.cpf?.[0]?.dadosBasicos;

    if (!json?.ok || !dados?.cpf) return null;

    const dataNascimento = normalizarData(dados.dataNascimento);
    console.log('Data original da API:', dados.dataNascimento, '→ normalizada:', dataNascimento);

    return {
      cpf: String(dados.cpf).replace(/\D/g, ''),
      nome: dados.nome,
      dataNascimento,
      sexo: dados.sexo
    };
  } catch (error) {
    console.error('Erro na CONSULTA_URL:', error);
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

// ─── ENDPOINTS PÚBLICOS ─────────────────────────────────

// POST /api/validate-cpf — consulta dados
app.post('/api/validate-cpf', async (req, res) => {
  const { cpf } = req.body;

  if (!cpf) {
    return res.status(400).json({ success: false, error: 'CPF obrigatório' });
  }

  const normalizedCpf = String(cpf).replace(/\D/g, '');

  if (normalizedCpf.length !== 11) {
    return res.status(400).json({ success: false, error: 'CPF inválido' });
  }

  try {
    // 1. Busca no cache do Supabase
    const { data: cached, error: cacheError } = await supabase
      .from('cpf_cache')
      .select('cpf, nome, data_nascimento, genero')
      .eq('cpf', normalizedCpf)
      .maybeSingle();

    if (cacheError) {
      console.error('Erro ao consultar cache:', cacheError);
      return res.status(500).json({ success: false, error: 'Erro ao consultar cache' });
    }

    // Encontrou no cache
    if (cached) {
      return res.json({
        success: true,
        cached: true,
        data: {
          cpf: cached.cpf,
          nome: cached.nome,
          // Garante que o frontend receba YYYY-MM-DD
          dataNascimento: normalizarData(cached.data_nascimento),
          sexo: cached.genero
        }
      });
    }

    // 2. Não tem cache → consulta API externa
    const data = await fetchCpfFromApi(normalizedCpf);

    if (!data) {
      return res.status(404).json({ success: false, error: 'CPF não encontrado' });
    }

    // 3. Salva no cpf_cache (genero = sexo da API)
    const { error: saveError } = await supabase
      .from('cpf_cache')
      .upsert({
        cpf: data.cpf,
        nome: data.nome,
        data_nascimento: data.dataNascimento,
        genero: data.sexo,
        consultado_em: new Date().toISOString()
      }, { onConflict: 'cpf' });

    if (saveError) {
      console.error('Erro ao salvar cache:', saveError);
    }

    // 4. Retorna o resultado da API
    return res.json({ success: true, cached: false, data });
  } catch (error) {
    console.error('Erro interno:', error);
    return res.status(500).json({ success: false, error: 'Erro interno' });
  }
});

/**
 * POST /api/create-payment — cria cobrança PIX REAL no brinox
 *
 * Mantém o MESMO formato de resposta que o frontend já espera:
 * { success, data: { hash, pixCode, amount, status } }
 */
app.post('/api/create-payment', async (req, res) => {
  const { cpf, nome, amount } = req.body;

  if (!cpf) {
    return res.status(400).json({ success: false, error: 'CPF obrigatório' });
  }

  const valor = Number(amount) || 198.38;
  const sessionToken = crypto.randomBytes(12).toString('hex'); // ID do seu lado

  if (!pixProvider.isConfigured()) {
    console.error('brinox não configurado: defina BRINOX_SECRET_KEY no .env');
    return res.status(500).json({ success: false, error: 'Gateway de pagamento não configurado' });
  }

  try {
    const charge = await pixProvider.createCharge({
      amount: valor,
      externalId: sessionToken,
    });

    // Persiste a cobrança no Supabase
    const { data: row, error } = await supabase
      .from('payments')
      .insert({
        session_token: sessionToken,
        pix_hash: charge.providerPaymentId,
        pix_code: charge.pixCode,
        amount: valor,
        status: charge.status === 'paid' ? 'paid' : 'pending',
        provider: 'brinox',
        provider_payment_id: charge.providerPaymentId,
        cpf: String(cpf).replace(/\D/g, ''),
        nome: nome || 'Cliente',
        created_at: new Date().toISOString(),
      })
      .select()
      .single();

    if (error) {
      console.error('Erro ao salvar cobrança:', error);
      return res.status(500).json({ success: false, error: 'Erro ao salvar cobrança' });
    }

    return res.json({
      success: true,
      data: {
        hash: sessionToken,                       // token p/ o front consultar status
        paymentId: charge.providerPaymentId,      // id no provedor
        pixCode: charge.pixCode,                  // copia-e-cola (EMV)
        qrCode: charge.qrCode,
        amount: valor,
        status: charge.status,
      },
    });
  } catch (err) {
    console.error('Erro ao criar cobrança no brinox:', err.message);

    if (err.name === 'PixProviderError') {
      return res.status(502).json({ success: false, error: `Falha no gateway: ${err.message}` });
    }

    return res.status(500).json({ success: false, error: 'Erro interno' });
  }
});

/**
 * POST /api/pix/webhook — recebe confirmação de pagamento do brinox
 *
 * Assinatura verificada com BRINOX_WEBHOOK_SECRET (whsec_...).
 * Responder SEMPRE com 200 (ou 2xx) após processar, senão o provedor reenvia.
 */
app.post('/api/pix/webhook', async (req, res) => {
  try {
    const event = pixProvider.verifyWebhook(req);

    console.log('Webhook recebido:', event);

    // Localiza a cobrança: primeiro pelo id do provedor, depois pelo external_id
    let { data: payment } = await supabase
      .from('payments')
      .select('id, session_token, status')
      .eq('provider_payment_id', event.providerPaymentId)
      .maybeSingle();

    if (!payment && event.externalId) {
      ({ data: payment } = await supabase
        .from('payments')
        .select('id, session_token, status')
        .eq('session_token', event.externalId)
        .maybeSingle());
    }

    if (!payment) {
      return res.status(404).json({ error: 'Pagamento não encontrado' });
    }

    const { error } = await supabase
      .from('payments')
      .update({
        status: event.status === 'paid' ? 'paid' : event.status,
        paid_at: event.status === 'paid' ? new Date().toISOString() : null,
        updated_at: new Date().toISOString(),
      })
      .eq('id', payment.id);

    if (error) {
      console.error('Erro ao atualizar pagamento via webhook:', error);
      return res.status(500).json({ error: 'Erro interno' });
    }

    return res.status(200).json({ received: true });
  } catch (err) {
    console.error('Webhook inválido:', err.message);
    return res.status(400).json({ error: err.message });
  }
});

// GET /api/payment-status/:token — consulta status pelo token da sessão
app.get('/api/payment-status/:token', async (req, res) => {
  const { data } = await supabase
    .from('payments')
    .select('*')
    .eq('session_token', req.params.token)
    .maybeSingle();

  if (!data) return res.status(404).json({ error: 'Pagamento não encontrado' });

  // Se estiver pendente, pergunta ao provedor (polling)
  let status = data.status;
  if (status === 'pending' && data.provider_payment_id) {
    try {
      const charge = await pixProvider.getCharge(data.provider_payment_id);
      status = charge.status;

      if (status !== data.status) {
        const { error } = await supabase
          .from('payments')
          .update({
            status,
            paid_at: status === 'paid' ? new Date().toISOString() : null,
            updated_at: new Date().toISOString(),
          })
          .eq('id', data.id);

        if (error) console.error('Erro ao atualizar status via polling:', error);
        else data.status = status;
      }
    } catch (err) {
      console.error('Erro ao consultar provedor:', err.message);
      // mantém o status atual do banco
    }
  }

  res.json({
    success: true,
    data: {
      hash: data.session_token,
      paymentId: data.provider_payment_id,
      pixCode: data.pix_code,
      amount: data.amount,
      status,
      paid_at: data.paid_at,
    },
  });
});

// GET /api/pix-session/:token — compat: front antigo continua funcionando
app.get('/api/pix-session/:token', async (req, res) => {
  const { data } = await supabase
    .from('pix_sessions')
    .select('*')
    .eq('token', req.params.token)
    .maybeSingle();

  // Se não achar em pix_sessions, tenta em payments (novo fluxo)
  if (!data) {
    const { data: payment } = await supabase
      .from('payments')
      .select('*')
      .eq('session_token', req.params.token)
      .maybeSingle();

    if (!payment) return res.status(404).json({ error: 'Sessão não encontrada' });

    return res.json({
      ...payment,
      status: payment.status,
      pixCode: payment.pix_code,
      paymentId: payment.provider_payment_id,
    });
  }

  res.json(data);
});

// GET /api/site-settings/logo — retorna logo pública
app.get('/api/site-settings/logo', async (req, res) => {
  const { data: logo } = await supabase.from('settings').select('value').eq('key', 'logo_url').single();
  const { data: size } = await supabase.from('settings').select('value').eq('key', 'logo_size').single();
  res.json({ url: logo?.value || '', size: parseInt(size?.value || '0') });
});

// ─── ENDPOINTS ADMIN (REQUER AUTH) ─────────────────────

// POST /api/admin/login
app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body;

  const { data: admin } = await supabase
    .from('admins')
    .select('*')
    .eq('username', username)
    .single();

  if (!admin) return res.status(401).json({ error: 'Credenciais inválidas' });

  const valid = (password === admin.password_hash); // Troque por bcrypt.compare() depois
  if (!valid) return res.status(401).json({ error: 'Credenciais inválidas' });

  const token = jwt.sign(
    { id: admin.id, username: admin.username, role: 'admin' },
    JWT_SECRET,
    { expiresIn: '24h' }
  );

  res.json({ success: true, token, data: { token }, message: "Login realizado com sucesso" });
});

// GET /api/admin/settings — credenciais do provedor PIX
app.get('/api/admin/settings', authMiddleware, async (req, res) => {
  const { data } = await supabase.from('settings').select('*');
  const settings = {};
  data.forEach(row => { settings[row.key] = row.value; });

  // Compat com o painel antigo (PixVault): devolve os campos que ele já usa
  return res.json({
    provider: settings.provider || 'brinox',
    base_url: settings.brinox_base_url || settings.base_url || '',
    public_key: settings.brinox_public_key || settings.public_key || '',
    // secret nunca volta no GET — só máscara
    secret_key_masked: settings.brinox_secret_key ? (settings.brinox_secret_key.slice(0, 7) + '...') : '',
    webhook_secret_masked: settings.brinox_webhook_secret ? (settings.brinox_webhook_secret.slice(0, 7) + '...') : '',
    pix_configured: pixProvider.isConfigured(), // true quando pk+sk+base_url estão preenchidos
    ...settings, // mantém qualquer outra chave existente
  });
});

// POST /api/admin/settings — atualizar credenciais do provedor PIX
// Aceita nomes brinox_* ou genéricos (base_url, public_key, secret_key, webhook_secret)
app.post('/api/admin/settings', authMiddleware, async (req, res) => {
  const {
    secondary_password,
    brinox_base_url, base_url,
    brinox_public_key, public_key,
    brinox_secret_key, secret_key,
    brinox_webhook_secret, webhook_secret,
  } = req.body;

  const { data: admin } = await supabase
    .from('admins')
    .select('secondary_password_hash')
    .eq('id', req.admin.id)
    .single();

  if (secondary_password !== admin.secondary_password_hash) {
    return res.status(403).json({ error: 'Senha secundária incorreta' });
  }

  const upserts = [
    { key: 'provider', value: 'brinox' },
  ];
  if (brinox_base_url || base_url) upserts.push({ key: 'brinox_base_url', value: brinox_base_url || base_url });
  if (brinox_public_key || public_key) upserts.push({ key: 'brinox_public_key', value: brinox_public_key || public_key });
  if (brinox_secret_key || secret_key) upserts.push({ key: 'brinox_secret_key', value: brinox_secret_key || secret_key });
  if (brinox_webhook_secret || webhook_secret) upserts.push({ key: 'brinox_webhook_secret', value: brinox_webhook_secret || webhook_secret });

  for (const row of upserts) {
    const { error } = await supabase.from('settings').upsert(row);
    if (error) {
      console.error('Erro ao salvar setting:', error);
      return res.status(500).json({ error: error.message });
    }
  }

  // Aplica na hora — sem precisar reiniciar o servidor
  const cfg = await pixProvider.loadConfig(supabase).catch(err => {
    console.error('Erro ao recarregar config:', err.message);
    return null;
  });
  if (cfg) pixProvider.applyConfig(cfg);

  res.json({ success: true, pix_configured: pixProvider.isConfigured() });
});

// GET /api/admin/receipts — listar comprovantes
app.get('/api/admin/receipts', authMiddleware, async (req, res) => {
  const { data } = await supabase.from('receipts').select('*').order('uploaded_at', { ascending: false });
  res.json(data || []);
});

// GET /api/admin/cpf-keys — listar chaves CPF
app.get('/api/admin/cpf-keys', authMiddleware, async (req, res) => {
  const { data } = await supabase.from('cpf_api_keys').select('*');
  res.json({ keys: data || [] });
});

// POST /api/admin/cpf-keys — adicionar chave CPF
app.post('/api/admin/cpf-keys', authMiddleware, async (req, res) => {
  const { secondary_password, key_name, api_key } = req.body;
  const { data: admin } = await supabase.from('admins').select('secondary_password_hash').eq('id', req.admin.id).single();
  if (secondary_password !== admin.secondary_password_hash) {
    return res.status(403).json({ error: 'Senha secundária incorreta' });
  }
  const { error } = await supabase.from('cpf_api_keys').insert({ key_name, api_key });
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// DELETE /api/admin/cpf-keys/:id
app.delete('/api/admin/cpf-keys/:id', authMiddleware, async (req, res) => {
  const { error } = await supabase.from('cpf_api_keys').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// GET /api/admin/cpf-cache-stats
app.get('/api/admin/cpf-cache-stats', authMiddleware, async (req, res) => {
  const { count } = await supabase.from('cpf_cache').select('*', { count: 'exact', head: true });
  const { count: sessionCount } = await supabase.from('pix_sessions').select('*', { count: 'exact', head: true });
  res.json({ total_cpfs: count || 0, total_sessions: sessionCount || 0 });
});

// GET /api/admin/payments — listar cobranças (novo)
app.get('/api/admin/payments', authMiddleware, async (req, res) => {
  const { data } = await supabase.from('payments').select('*').order('created_at', { ascending: false }).limit(200);
  res.json({ payments: data || [] });
});

// ─── INICIAR SERVIDOR ────────────────────────────────────
async function start() {
  // Carrega a config do provedor da tabela settings (Supabase),
  // com fallback para as envs — permite configurar tudo pelo /admin
  try {
    const cfg = await pixProvider.loadConfig(supabase);
    if (cfg) pixProvider.applyConfig(cfg);
  } catch (err) {
    console.error('Erro ao carregar config inicial:', err.message);
  }

  app.listen(PORT, () => {
    console.log(`Backend rodando em http://localhost:${PORT}`);
    console.log('Endpoints disponíveis:');
    console.log('  POST /api/validate-cpf');
    console.log('  POST /api/create-payment      (brinox)');
    console.log('  POST /api/pix/webhook         (brinox, assinado)');
    console.log('  GET  /api/payment-status/:token');
    console.log('  GET  /api/pix-session/:token');
    console.log('  POST /api/upload-receipt');
    console.log('  POST /api/admin/login');
    console.log('  GET/POST /api/admin/settings  (auth)');
    console.log('  GET  /api/admin/receipts      (auth)');
    console.log('  GET  /api/admin/payments      (auth)');
    console.log(`Provedor PIX: ${pixProvider.isConfigured() ? 'brinox (configurado)' : 'NÃO CONFIGURADO — preencha em /admin (settings) ou envs BRINOX_*'}`);
  });
}

start();
