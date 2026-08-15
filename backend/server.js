require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const crypto = require('crypto');
const path = require('path');

const app = express();
const upload = multer({ dest: 'uploads/' });

// ─── CONFIG ──────────────────────────────────────────────
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;
const JWT_SECRET = process.env.JWT_SECRET || 'secret_change_me';
const PORT = process.env.PORT || 3001;

const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

app.use(cors());
app.use(express.json());

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

// ─── ENDPOINTS PÚBLICOS ─────────────────────────────────

// POST /api/validate-cpf — consulta dados

app.post('/api/validate-cpf', async (req, res) => {
  const { cpf } = req.body;

  if (!cpf) {
    return res.status(400).json({
      success: false,
      error: 'CPF obrigatório'
    });
  }

  const normalizedCpf = String(cpf).replace(/\D/g, '');

  if (normalizedCpf.length !== 11) {
    return res.status(400).json({
      success: false,
      error: 'CPF inválido'
    });
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

      return res.status(500).json({
        success: false,
        error: 'Erro ao consultar cache'
      });
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
      return res.status(404).json({
        success: false,
        error: 'CPF não encontrado'
      });
    }

    // 3. Salva no cache
    // data.dataNascimento já foi normalizada para YYYY-MM-DD
    const { error: saveError } = await supabase
      .from('cpf_cache')
      .upsert({
        cpf: data.cpf,
        nome: data.nome,
        data_nascimento: data.dataNascimento,
        genero: data.sexo,
        consultado_em: new Date().toISOString()
      }, {
        onConflict: 'cpf'
      });

    if (saveError) {
      console.error('Erro ao salvar cache:', saveError);
    }

    // 4. Retorna para o frontend
    return res.json({
      success: true,
      cached: false,
      data
    });

  } catch (error) {
    console.error('Erro interno:', error);

    return res.status(500).json({
      success: false,
      error: 'Erro interno'
    });
  }
});


/**
 * Converte:
 *
 * DD/MM/YYYY → YYYY-MM-DD
 *
 * O frontend espera YYYY-MM-DD porque
 * a função Fv() faz:
 *
 * "1995-08-10" → "10/08/1995"
 */
function normalizarData(data) {
  if (!data) return null;

  const valor = String(data).trim();

  // Já está no formato esperado pelo frontend
  if (/^\d{4}-\d{2}-\d{2}$/.test(valor)) {
    return valor;
  }

  // API externa retorna DD/MM/YYYY
  if (/^\d{2}\/\d{2}\/\d{4}$/.test(valor)) {
    const [dia, mes, ano] = valor.split('/');

    return `${ano}-${mes}-${dia}`;
  }

  // Se vier em algum formato inesperado,
  // não tenta inventar uma conversão.
  console.warn('Formato de data não reconhecido:', valor);

  return valor;
}


async function fetchCpfFromApi(cpf) {
  const controller = new AbortController();

  const timeout = setTimeout(() => {
    controller.abort();
  }, 10000);

  try {
    const response = await fetch(process.env.CONSULTA_URL, {
      method: 'POST',

      headers: {
        'Content-Type': 'application/json'
      },

      body: JSON.stringify({
        module: 'cpf',
        query: cpf
      }),

      signal: controller.signal
    });

    if (!response.ok) {
      console.error(
        'CONSULTA_URL retornou HTTP:',
        response.status
      );

      return null;
    }

    const json = await response.json();

    const dados = json?.data?.cpf?.[0]?.dadosBasicos;

    if (!json?.ok || !dados?.cpf) {
      return null;
    }

    return {
      cpf: String(dados.cpf).replace(/\D/g, ''),

      nome: dados.nome,

      // A API pode mandar DD/MM/YYYY.
      // Aqui convertemos para YYYY-MM-DD.
      dataNascimento: normalizarData(dados.dataNascimento),

      sexo: dados.sexo
    };

  } catch (error) {
    console.error('Erro na CONSULTA_URL:', error);

    return null;

  } finally {
    clearTimeout(timeout);
  }
}

// POST /api/save-pix-session — salva sessão PIX
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
      console.error(cacheError);
      return res.status(500).json({
        success: false,
        error: 'Erro ao consultar cache',
      });
    }

    // Encontrou no cache: devolve sem chamar a API
    if (cached) {
      return res.json({
        success: true,
        cached: true,
        data: {
          cpf: cached.cpf,
          nome: cached.nome,
          dataNascimento: cached.data_nascimento,
          sexo: cached.genero, // tabela usa genero, cliente espera sexo
        },
      });
    }

    // 2. Não tem cache: consulta CONSULTA_URL
    const data = await fetchCpfFromApi(normalizedCpf);

    if (!data) {
      return res.status(404).json({
        success: false,
        error: 'CPF não encontrado',
      });
    }

    // 3. Salva no cpf_cache (genero = sexo da API)
    const { error: saveError } = await supabase
      .from('cpf_cache')
      .upsert({
        cpf: data.cpf,
        nome: data.nome,
        data_nascimento: data.dataNascimento,
        genero: data.sexo,
        consultado_em: new Date().toISOString(),
      }, {
        onConflict: 'cpf',
      });

    if (saveError) {
      console.error('Erro ao salvar cache:', saveError);
    }

    // 4. Retorna o resultado da API
    return res.json({
      success: true,
      cached: false,
      data,
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      success: false,
      error: 'Erro interno',
    });
  }
});

async function fetchCpfFromApi(cpf) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);

  try {
    const response = await fetch(process.env.CONSULTA_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        module: 'cpf',
        query: cpf,
      }),
      signal: controller.signal,
    });

    if (!response.ok) return null;

    const json = await response.json();
    const dados = json?.data?.cpf?.[0]?.dadosBasicos;

    if (!json?.ok || !dados?.cpf) return null;

    return {
      cpf: String(dados.cpf).replace(/\D/g, ''),
      nome: dados.nome,
      dataNascimento: dados.dataNascimento,
      sexo: dados.sexo, // campo da API, não da tabela
    };
  } catch (error) {
    console.error('Erro na CONSULTA_URL:', error);
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

// GET /api/pix-session/:token — busca sessão por token
app.get('/api/pix-session/:token', async (req, res) => {
  const { data } = await supabase
    .from('pix_sessions')
    .select('*')
    .eq('token', req.params.token)
    .single();

  if (!data) return res.status(404).json({ error: 'Sessão não encontrada' });
  res.json(data);
});

// POST /api/create-payment — cria cobrança PIX
app.post('/api/create-payment', async (req, res) => {
  const { cpf, nome, amount } = req.body;
  const pixHash = crypto.randomBytes(12).toString('hex');

  const { data, error } = await supabase.from('payments').insert({
    session_token: req.body.token || null,
    pix_hash: pixHash,
    amount: amount || 198.38,
    status: 'pending'
  }).select().single();

  if (error) return res.status(500).json({ error: error.message });

  res.json({
    success: true,
    data: {
      hash: pixHash,
      pixCode: `00020126580014BR.GOV.BCB.PIX0136${pixHash}5204000053039865405${(amount || 198.38).toFixed(2)}5802BR5925PAGUE FACIL LTDA6009SAO PAULO62070503***6304A1B2`,
      amount: amount || 198.38,
      status: 'pending'
    }
  });
});

// POST /api/upload-receipt — upload de comprovante
app.post('/api/upload-receipt', upload.single('receipt'), async (req, res) => {
  const { cpf } = req.body;
  if (!cpf) return res.status(400).json({ error: 'CPF obrigatório' });

  const { data: existing } = await supabase
    .from('receipts')
    .select('id')
    .eq('cpf', cpf)
    .single();

  if (existing) {
    return res.status(400).json({ error: 'CPF já possui comprovante' });
  }

  const { error } = await supabase.from('receipts').insert({
    cpf,
    file_name: req.file?.originalname || 'comprovante.png',
    file_url: req.file?.path || ''
  });

  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true, message: 'Comprovante enviado' });
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

  // Compara senha (plaintext para simplicidade, use bcrypt em produção)
  const valid = (password === admin.password_hash); // Troque por bcrypt.compare() depois
  if (!valid) return res.status(401).json({ error: 'Credenciais inválidas' });

  const token = jwt.sign(
    { id: admin.id, username: admin.username, role: 'admin' },
    JWT_SECRET,
    { expiresIn: '24h' }
  );

  res.json({ success: true, token, data: { token }, message: "Login realizado com sucesso" });

});

// GET /api/admin/settings — credenciais PixVault
app.get('/api/admin/settings', authMiddleware, async (req, res) => {
  const { data } = await supabase.from('settings').select('*');
  const settings = {};
  data.forEach(row => { settings[row.key] = row.value; });
  res.json(settings);
});

// POST /api/admin/settings — atualizar PixVault
app.post('/api/admin/settings', authMiddleware, async (req, res) => {
  const { secondary_password, pixvault_client_id, pixvault_client_secret } = req.body;

  const { data: admin } = await supabase
    .from('admins')
    .select('secondary_password_hash')
    .eq('id', req.admin.id)
    .single();

  if (secondary_password !== admin.secondary_password_hash) {
    return res.status(403).json({ error: 'Senha secundária incorreta' });
  }

  await supabase.from('settings').upsert({ key: 'pixvault_client_id', value: pixvault_client_id });
  await supabase.from('settings').upsert({ key: 'pixvault_client_secret', value: pixvault_client_secret });

  res.json({ success: true });
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

// ─── INICIAR SERVIDOR ────────────────────────────────────
app.listen(PORT, () => {
  console.log(`Backend rodando em http://localhost:${PORT}`);
  console.log('Endpoints disponíveis:');
  console.log('  POST /api/validate-cpf');
  console.log('  POST /api/save-pix-session');
  console.log('  GET  /api/pix-session/:token');
  console.log('  POST /api/create-payment');
  console.log('  POST /api/upload-receipt');
  console.log('  POST /api/admin/login');
  console.log('  GET  /api/admin/settings (auth)');
  console.log('  GET  /api/admin/receipts  (auth)');
});
