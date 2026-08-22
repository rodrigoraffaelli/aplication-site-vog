console.log('### VERSAO PIX-BRINOX 2026-08-22b ###');
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
// URL base pública usada p/ gerar links absolutos (logo, comprovantes)
const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL || 'https://aplication-site-vog.onrender.com';

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

app.use(cors());
// rawBody é necessário para verificar a assinatura do webhook
app.use(express.json({ verify: (req, res, buf) => { req.rawBody = buf; } }));
// Arquivos enviados (comprovantes e logos) ficam na pasta uploads/
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

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

// POST /api/save-pix-session — salva a sessão PIX exibida na página /pagamento
// Front envia: { pixCode, nome, cpf, dataNascimento, amount } e espera { success, token }
app.post('/api/save-pix-session', async (req, res) => {
  const { pixCode, nome, cpf, dataNascimento, amount } = req.body || {};

  if (!pixCode || !nome || !cpf) {
    return res.status(400).json({ success: false, error: 'Dados incompletos da sessão PIX' });
  }

  const token = crypto.randomBytes(16).toString('hex');
  // amount vem formatado em pt-BR (ex: "198,38") — converte para número
  const valor = Number(String(amount || '0').replace(/\./g, '').replace(',', '.')) || 0;
  const ttlMin = parseInt(process.env.PIX_SESSION_TTL_MINUTES || '15', 10) || 15;
  const expiresAt = new Date(Date.now() + ttlMin * 60 * 1000).toISOString();

  const { error } = await supabase.from('pix_sessions').insert({
    token,
    pix_code: String(pixCode),
    nome: String(nome),
    cpf: String(cpf).replace(/\D/g, ''),
    data_nascimento: normalizarData(dataNascimento),
    amount: valor,
    expires_at: expiresAt,
  });

  if (error) {
    console.error('Erro ao salvar pix_session:', error);
    return res.status(500).json({ success: false, error: 'Erro ao salvar sessão' });
  }

  res.json({ success: true, token });
});

// GET /api/pix-session/:token — página /pix/:token
// Formato esperado pelo front: { expired, data: { pixCode, nome, cpf, dataNascimento, expiresAt } }
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

    const expires = payment.expires_at ? new Date(payment.expires_at) : null;
    return res.json({
      expired: expires ? expires.getTime() <= Date.now() : false,
      data: {
        pixCode: payment.pix_code,
        nome: payment.nome,
        cpf: payment.cpf,
        dataNascimento: normalizarData(payment.data_nascimento),
        expiresAt: payment.expires_at || payment.created_at,
        amount: payment.amount,
      },
    });
  }

  const expires = data.expires_at ? new Date(data.expires_at) : null;
  res.json({
    expired: expires ? expires.getTime() <= Date.now() : false,
    data: {
      pixCode: data.pix_code,
      nome: data.nome,
      cpf: data.cpf,
      dataNascimento: normalizarData(data.data_nascimento),
      expiresAt: data.expires_at,
      amount: data.amount,
    },
  });
});

// GET /api/site-settings/logo — retorna logo pública
app.get('/api/site-settings/logo', async (req, res) => {
  const { data: logo } = await supabase.from('settings').select('value').eq('key', 'logo_url').single();
  const { data: size } = await supabase.from('settings').select('value').eq('key', 'logo_size').single();
  res.json({ url: logo?.value || '', size: parseInt(size?.value || '0') });
});

// POST /api/upload-receipt — cliente envia o comprovante (multipart: file, cpf, nome)
app.post('/api/upload-receipt', upload.single('file'), async (req, res) => {
  const cpf = String(req.body?.cpf || '').replace(/\D/g, '');
  const nome = String(req.body?.nome || '').trim();

  if (!req.file) {
    return res.status(400).json({ success: false, error: 'Nenhum arquivo enviado' });
  }
  if (!cpf) {
    return res.status(400).json({ success: false, error: 'CPF obrigatório' });
  }

  // Evita comprovante duplicado para o mesmo CPF
  const { data: existente } = await supabase
    .from('receipts')
    .select('id')
    .eq('cpf', cpf)
    .maybeSingle();
  if (existente) {
    return res.status(409).json({ success: false, error: 'Comprovante já enviado para este CPF' });
  }

  const { error } = await supabase.from('receipts').insert({
    cpf,
    nome,
    file_name: req.file.originalname,
    file_url: req.file.path,
    uploaded_at: new Date().toISOString(),
  });

  if (error) {
    console.error('Erro ao salvar comprovante:', error);
    return res.status(500).json({ success: false, error: 'Erro ao salvar comprovante' });
  }

  res.json({ success: true, message: 'Comprovante enviado' });
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
// Compat total com o painel antigo (labels PixVault: Client ID / Token Secret)
app.get('/api/admin/settings', authMiddleware, async (req, res) => {
  const { data } = await supabase.from('settings').select('*');
  const settings = {};
  (data || []).forEach(row => { settings[row.key] = row.value; });

  const publicKey = settings.brinox_public_key || settings.public_key || settings.pixvault_client_id || '';
  const secretKey = settings.brinox_secret_key || settings.secret_key || settings.pixvault_client_secret || '';
  const baseUrl = settings.brinox_base_url || settings.base_url || 'https://api.brinoxcargo.shop/v1';
  const webhookSecret = settings.brinox_webhook_secret || settings.webhook_secret || '';

  return res.json({
    ...settings,
    provider: settings.provider || 'brinox',
    base_url: baseUrl,
    public_key: publicKey,
    // Campos que o painel /admin lê (aliases legados PixVault p/ compat):
    pixvault_client_id: publicKey,
    pixvault_client_secret: secretKey,
    pixvault_token_secret: secretKey,
    // máscaras úteis se algum painel novo consumir
    secret_key_masked: secretKey ? (secretKey.slice(0, 7) + '...') : '',
    webhook_secret_masked: webhookSecret ? (webhookSecret.slice(0, 7) + '...') : '',
    pix_configured: !!(publicKey && secretKey && baseUrl),
  });
});

// POST/PUT /api/admin/settings — atualizar credenciais do provedor PIX
// O painel /admin envia PUT com { brinox_public_key, brinox_secret_key, secondary_password }.
// Aceita também nomes antigos (pixvault_*, client_id, token_secret) p/ compatibilidade.
// Senha secundária: se o front NÃO enviar, só exige JWT admin (authMiddleware já validou).
async function handleSaveSettings(req, res) {
  const body = req.body || {};
  const {
    secondary_password,
    brinox_base_url, base_url,
    brinox_public_key, public_key, pixvault_client_id, client_id,
    brinox_secret_key, secret_key, pixvault_client_secret, token_secret, client_secret,
    pixvault_token_secret,
    brinox_webhook_secret, webhook_secret,
  } = body;

  // Só valida senha secundária se o front mandar o campo (painel antigo às vezes não manda)
  if (secondary_password !== undefined && secondary_password !== null && String(secondary_password).length > 0) {
    const { data: admin } = await supabase
      .from('admins')
      .select('secondary_password_hash')
      .eq('id', req.admin.id)
      .single();

    if (!admin || secondary_password !== admin.secondary_password_hash) {
      return res.status(403).json({ error: 'Senha secundária incorreta' });
    }
  }

  const pk =
    brinox_public_key || public_key || pixvault_client_id || client_id || '';
  const sk =
    brinox_secret_key || secret_key || pixvault_client_secret || token_secret || client_secret || pixvault_token_secret || '';
  const base =
    brinox_base_url || base_url || 'https://api.brinoxcargo.shop/v1';
  const whsec = brinox_webhook_secret || webhook_secret || '';

  const upserts = [
    { key: 'provider', value: 'brinox' },
    { key: 'brinox_base_url', value: String(base).trim() },
  ];
  if (pk) upserts.push({ key: 'brinox_public_key', value: String(pk).trim() });
  if (sk) upserts.push({ key: 'brinox_secret_key', value: String(sk).trim() });
  if (whsec) upserts.push({ key: 'brinox_webhook_secret', value: String(whsec).trim() });

  // Mantém linhas legadas preenchidas p/ o form antigo continuar mostrando os valores
  if (pk) upserts.push({ key: 'pixvault_client_id', value: String(pk).trim() });
  if (sk) upserts.push({ key: 'pixvault_client_secret', value: String(sk).trim() });

  for (const row of upserts) {
    const { error } = await supabase.from('settings').upsert(row, { onConflict: 'key' });
    if (error) {
      // fallback se a PK da tabela não for "key"
      const { error: err2 } = await supabase.from('settings').upsert(row);
      if (err2) {
        console.error('Erro ao salvar setting:', err2);
        return res.status(500).json({ error: err2.message });
      }
    }
  }

  // Aplica na hora — sem precisar reiniciar o servidor
  const cfg = await pixProvider.loadConfig(supabase).catch(err => {
    console.error('Erro ao recarregar config:', err.message);
    return null;
  });
  if (cfg) pixProvider.applyConfig(cfg);

  res.json({
    success: true,
    message: 'Configuração PIX (brinox) salva',
    pix_configured: pixProvider.isConfigured(),
    provider: 'brinox',
  });
}

app.post('/api/admin/settings', authMiddleware, handleSaveSettings);
app.put('/api/admin/settings', authMiddleware, handleSaveSettings);

// POST /api/admin/upload-logo — envia imagem da logo (multipart: file + secondary_password)
// Retorna { url } — o painel depois chama PUT /api/admin/settings/logo para salvar.
app.post('/api/admin/upload-logo', authMiddleware, upload.single('file'), async (req, res) => {
  const secondary_password = String(req.body?.secondary_password || '');
  const { data: admin } = await supabase.from('admins').select('secondary_password_hash').eq('id', req.admin.id).single();
  if (!admin || secondary_password !== admin.secondary_password_hash) {
    return res.status(403).json({ error: 'Senha secundária incorreta' });
  }
  if (!req.file) {
    return res.status(400).json({ error: 'Nenhum arquivo enviado' });
  }
  res.json({ url: `${PUBLIC_BASE_URL}/uploads/${req.file.filename}` });
});

// PUT /api/admin/settings/logo — salva logo_url / logo_size nas settings
app.put('/api/admin/settings/logo', authMiddleware, async (req, res) => {
  const { logo_url, logo_size, secondary_password } = req.body || {};
  const { data: admin } = await supabase.from('admins').select('secondary_password_hash').eq('id', req.admin.id).single();
  if (!admin || secondary_password !== admin.secondary_password_hash) {
    return res.status(403).json({ error: 'Senha secundária incorreta' });
  }

  const upserts = [];
  if (logo_url) upserts.push({ key: 'logo_url', value: String(logo_url).trim() });
  if (logo_size) upserts.push({ key: 'logo_size', value: String(logo_size) });

  for (const row of upserts) {
    const { error } = await supabase.from('settings').upsert(row, { onConflict: 'key' });
    if (error) return res.status(500).json({ error: error.message });
  }

  res.json({ success: true, message: 'Logo atualizada!' });
});

// GET /api/admin/receipts — listar comprovantes
app.get('/api/admin/receipts', authMiddleware, async (req, res) => {
  const { data } = await supabase.from('receipts').select('*').order('uploaded_at', { ascending: false });
  res.json({ receipts: data || [] });
});

// GET /api/admin/receipts/:id/download — baixar/visualizar comprovante
app.get('/api/admin/receipts/:id/download', authMiddleware, async (req, res) => {
  const { data: receipt } = await supabase.from('receipts').select('*').eq('id', req.params.id).maybeSingle();
  if (!receipt) return res.status(404).json({ error: 'Comprovante não encontrado' });

  const fileUrl = receipt.file_url || receipt.file_path || '';
  if (!fileUrl) return res.status(404).json({ error: 'Arquivo não encontrado' });

  // URL externa (Supabase storage, CDN...) → redireciona
  if (/^https?:\/\//.test(fileUrl)) {
    return res.redirect(fileUrl);
  }

  const abs = path.resolve(fileUrl);
  res.download(abs, receipt.file_name || path.basename(fileUrl), (err) => {
    if (err && !res.headersSent) {
      return res.status(404).json({ error: 'Arquivo não encontrado no servidor' });
    }
  });
});

// DELETE /api/admin/receipts/:id — excluir comprovante
app.delete('/api/admin/receipts/:id', authMiddleware, async (req, res) => {
  const { data: receipt } = await supabase.from('receipts').select('file_url, file_path').eq('id', req.params.id).maybeSingle();

  const { error } = await supabase.from('receipts').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });

  // Remove o arquivo local (ignora falha — não derruba a resposta)
  if (receipt) {
    const local = (receipt.file_url || receipt.file_path || '');
    if (local && !/^https?:\/\//.test(local)) {
      try { require('fs').unlinkSync(path.resolve(local)); } catch (_) { /* arquivo já não existe */ }
    }
  }

  res.json({ success: true });
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
    console.log('  POST /api/save-pix-session');
    console.log('  POST /api/upload-receipt');
    console.log('  POST /api/admin/login');
    console.log('  GET/POST/PUT /api/admin/settings      (auth)');
    console.log('  POST /api/admin/upload-logo           (auth)');
    console.log('  PUT  /api/admin/settings/logo         (auth)');
    console.log('  GET  /api/admin/receipts              (auth)');
    console.log('  GET  /api/admin/receipts/:id/download (auth)');
    console.log('  DELETE /api/admin/receipts/:id        (auth)');
    console.log('  GET  /api/admin/payments              (auth)');
    console.log(`Provedor PIX: ${pixProvider.isConfigured() ? 'brinox (configurado)' : 'NÃO CONFIGURADO — preencha em /admin (settings) ou envs BRINOX_*'}`);
  });
}

start();
