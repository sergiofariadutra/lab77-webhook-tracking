/**
 * LAB77 / GRUPO 77
 * Webhook: Frete Barato → Bling
 * v4.0 — Correção definitiva: OAuth2, persistência e retry
 */

require("dotenv").config();
const express = require("express");
const axios = require("axios");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();

app.use(express.json({
  verify: (req, res, buf) => { req.rawBody = buf; }
}));

// Rate limiting simples
const rateLimitMap = new Map();
function rateLimit(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress || "unknown";
  const agora = Date.now();
  const janela = 60 * 1000;
  const limite = 100;
  const registro = rateLimitMap.get(ip) || { count: 0, inicio: agora };
  if (agora - registro.inicio > janela) { registro.count = 0; registro.inicio = agora; }
  registro.count++;
  rateLimitMap.set(ip, registro);
  if (rateLimitMap.size > 1000) {
    for (const [key, val] of rateLimitMap.entries()) {
      if (agora - val.inicio > janela) rateLimitMap.delete(key);
    }
  }
  if (registro.count > limite) return res.status(429).json({ error: "muitas requisições" });
  next();
}

// ============================================================
// CONFIGURAÇÕES
// ============================================================
const CONFIG = {
  bling: {
    clientId: process.env.BLING_CLIENT_ID,
    clientSecret: process.env.BLING_CLIENT_SECRET,
    baseUrl: "https://www.bling.com.br/Api/v3",
    webhookSecret: process.env.BLING_WEBHOOK_SECRET,
  },
  freteBarato: {
    token: process.env.FRETEBARATO_TOKEN,
    customerId: process.env.FRETEBARATO_CUSTOMER_ID,
    plataforma: process.env.FRETEBARATO_PLATAFORMA || "shopify",
    baseUrl: "https://admin.fretebarato.com",
  },
  empresa: { cnpj: process.env.EMPRESA_CNPJ },
  servidor: {
    apiKey: process.env.WEBHOOK_API_KEY,
    baseUrl: process.env.BASE_URL || "http://localhost:3000",
  },
  retry: { tentativas: 6, intervaloMs: 30000 },
};

const fila = new Map();
const etiquetas = new Map();
const emProcessamento = new Set();
function sleep(ms) { return new Promise((resolve) => setTimeout(resolve, ms)); }
function log(nivel, mensagem, dados = null) {
  const ts = new Date().toISOString();
  console.log(`[${ts}] [${nivel}] ${mensagem}`);
  if (dados) console.log(JSON.stringify(dados, null, 2));
}

// ============================================================
// TOKENS BLING — Persistência + Refresh
// Usa /data se existir (Railway Volume), senão __dirname
// ============================================================
const STORAGE_DIR = process.env.TOKEN_STORAGE_PATH || (fs.existsSync("/data") ? "/data" : __dirname);
const TOKEN_FILE = path.join(STORAGE_DIR, ".bling-tokens.json");

let tokens = {
  accessToken: null,
  refreshToken: process.env.BLING_REFRESH_TOKEN || null,
  expiresAt: 0,
};

function salvarTokens() {
  try {
    fs.writeFileSync(TOKEN_FILE, JSON.stringify(tokens, null, 2));
    log("INFO", "Tokens salvos em disco");
  } catch (err) {
    log("AVISO", "Falha ao salvar tokens em disco (normal se não tem volume)", { error: err.message });
  }
}

function carregarTokensDoDisco() {
  try {
    if (fs.existsSync(TOKEN_FILE)) {
      const data = JSON.parse(fs.readFileSync(TOKEN_FILE, "utf-8"));
      if (data.accessToken) tokens.accessToken = data.accessToken;
      if (data.refreshToken) tokens.refreshToken = data.refreshToken;
      if (data.expiresAt) tokens.expiresAt = data.expiresAt;
      log("INFO", "Tokens carregados do disco", {
        temAccess: !!data.accessToken,
        temRefresh: !!data.refreshToken,
        expira: new Date(data.expiresAt).toISOString(),
      });
      return true;
    }
  } catch (err) {
    log("AVISO", "Erro ao ler tokens do disco");
  }
  return false;
}

function basicAuth() {
  return "Basic " + Buffer.from(`${CONFIG.bling.clientId}:${CONFIG.bling.clientSecret}`).toString("base64");
}

async function refreshToken() {
  if (!tokens.refreshToken) {
    throw new Error("Sem refresh_token — faça OAuth via /authorize");
  }
  log("INFO", "Renovando token Bling...");
  const res = await axios.post(
    `${CONFIG.bling.baseUrl}/oauth/token`,
    new URLSearchParams({ grant_type: "refresh_token", refresh_token: tokens.refreshToken }),
    {
      headers: { Authorization: basicAuth(), "Content-Type": "application/x-www-form-urlencoded" },
      timeout: 15000,
    }
  );
  tokens.accessToken = res.data.access_token;
  tokens.refreshToken = res.data.refresh_token;
  tokens.expiresAt = Date.now() + (res.data.expires_in * 1000) - 120000; // renova 2min antes
  salvarTokens();
  log("OK", "Token Bling renovado", { expires_in: res.data.expires_in });
}

// Garante token válido — usado antes de cada chamada ao Bling
async function getAccessToken() {
  if (tokens.accessToken && Date.now() < tokens.expiresAt) {
    return tokens.accessToken;
  }
  await refreshToken();
  return tokens.accessToken;
}

// Chamada ao Bling com retry automático em caso de 401
async function blingRequest(method, urlPath, data = null) {
  const url = `${CONFIG.bling.baseUrl}${urlPath}`;
  const accessToken = await getAccessToken();

  const config = {
    method,
    url,
    headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
    timeout: 10000,
  };
  if (data) config.data = data;

  try {
    return await axios(config);
  } catch (err) {
    if (err.response?.status === 401) {
      log("AVISO", "401 do Bling — forçando refresh e tentando de novo...");
      tokens.expiresAt = 0; // forçar refresh
      const novoToken = await getAccessToken();
      config.headers.Authorization = `Bearer ${novoToken}`;
      return await axios(config); // se falhar de novo, propaga o erro
    }
    throw err;
  }
}

// ============================================================
// Inicialização de tokens — tenta disco, depois env var, depois espera OAuth
// ============================================================
async function inicializarTokens() {
  // 1. Tenta carregar do disco (Railway Volume ou restart sem redeploy)
  if (carregarTokensDoDisco()) {
    // Se tem access token e não expirou, tudo ok
    if (tokens.accessToken && Date.now() < tokens.expiresAt) {
      log("OK", "Token do disco ainda válido");
      return;
    }
    // Se tem refresh token, tenta renovar
    if (tokens.refreshToken) {
      try {
        await refreshToken();
        log("OK", "Token renovado a partir do disco");
        return;
      } catch (err) {
        log("AVISO", "Refresh do disco falhou", { error: err.response?.data || err.message });
      }
    }
  }

  // 2. Tenta refresh via env var
  if (process.env.BLING_REFRESH_TOKEN) {
    tokens.refreshToken = process.env.BLING_REFRESH_TOKEN;
    try {
      await refreshToken();
      log("OK", "Token obtido via BLING_REFRESH_TOKEN env var");
      return;
    } catch (err) {
      log("AVISO", "BLING_REFRESH_TOKEN env var inválido/expirado", { error: err.response?.data || err.message });
    }
  }

  // 3. Sem token — precisa de OAuth manual
  log("AVISO", "=== SEM TOKEN BLING ===");
  log("AVISO", `Acesse: ${CONFIG.servidor.baseUrl}/authorize`);
}

// ============================================================
// VERIFICAÇÃO DE ASSINATURA DO BLING (HMAC-SHA256)
// ============================================================
function verificarAssinaturaBling(req) {
  if (!CONFIG.bling.webhookSecret) return true;
  const assinatura = req.headers["x-bling-signature"] || req.headers["x-signature"];
  if (!assinatura) { log("ERRO", "Webhook sem assinatura"); return false; }
  const hmac = crypto.createHmac("sha256", CONFIG.bling.webhookSecret).update(req.rawBody).digest("hex");
  try {
    const esperada = `sha256=${hmac}`;
    if (assinatura.length !== esperada.length) return false;
    return crypto.timingSafeEqual(Buffer.from(assinatura), Buffer.from(esperada));
  } catch { return false; }
}

function autenticarApiKey(req, res, next) {
  if (!CONFIG.servidor.apiKey) return next();
  const key = req.headers["x-api-key"];
  if (!key || key !== CONFIG.servidor.apiKey) return res.status(401).json({ error: "não autorizado" });
  next();
}

// ============================================================
// OAUTH — /oauth/callback e /authorize
// ============================================================
app.get("/oauth/callback", async (req, res) => {
  const { code } = req.query;
  if (!code) return res.status(400).json({ error: "Parâmetro 'code' ausente" });

  try {
    const response = await axios.post(
      `${CONFIG.bling.baseUrl}/oauth/token`,
      new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: `${CONFIG.servidor.baseUrl}/oauth/callback`,
      }),
      {
        headers: { Authorization: basicAuth(), "Content-Type": "application/x-www-form-urlencoded" },
        timeout: 15000,
      }
    );

    tokens.accessToken = response.data.access_token;
    tokens.refreshToken = response.data.refresh_token;
    tokens.expiresAt = Date.now() + (response.data.expires_in * 1000) - 120000;
    salvarTokens();

    log("OK", "=== OAUTH CONCLUÍDO ===");
    log("OK", `Novo refresh_token para env var: ${tokens.refreshToken}`);

    res.send(`
      <html><body style="font-family:monospace;padding:40px;background:#1a1a2e;color:#0f0">
        <h1>✅ OAuth concluído!</h1>
        <p>Tokens salvos. O webhook está pronto.</p>
        <p>Expira em: ${new Date(tokens.expiresAt).toISOString()}</p>
        <hr>
        <p><strong>IMPORTANTE — Copie o refresh_token abaixo e cole na variável<br>
        BLING_REFRESH_TOKEN no Railway (para sobreviver a redeploys):</strong></p>
        <textarea rows="3" cols="80" onclick="this.select()">${tokens.refreshToken}</textarea>
        <p>Depois de colar no Railway, NÃO clique em "Redeploy" — o app já está funcionando.</p>
      </body></html>
    `);
  } catch (err) {
    log("ERRO", "OAuth falhou", { error: err.message, data: err.response?.data });
    res.status(500).json({ error: "OAuth falhou", detalhes: err.response?.data || err.message });
  }
});

app.get("/authorize", (req, res) => {
  const url = `https://www.bling.com.br/Api/v3/oauth/authorize?response_type=code&client_id=${CONFIG.bling.clientId}&state=lab77`;
  res.redirect(url);
});

// ============================================================
// FRETE BARATO — Buscar tracking
// ============================================================
async function buscarTrackingFreteBarato(chaveNF) {
  const url = `${CONFIG.freteBarato.baseUrl}/${CONFIG.freteBarato.plataforma}/tracking/v1/json/${CONFIG.freteBarato.customerId}`;
  try {
    const response = await axios.get(url, {
      data: { cnpj: CONFIG.empresa.cnpj, nota_fiscal_id: chaveNF },
      headers: {
        Authorization: `Bearer ${CONFIG.freteBarato.token}`,
        Accept: "application/json",
        "Content-Type": "application/json",
        "User-Agent": "LAB77-Webhook",
      },
      timeout: 10000,
    });
    const invoice = response.data?.invoice;
    if (!invoice || !invoice.trackCode) return null;
    return invoice.trackCode;
  } catch (err) {
    const status = err.response?.status;
    if (status === 404) return null;
    if (err.code === "ECONNABORTED" || err.code === "ETIMEDOUT") {
      log("AVISO", "Timeout Frete Barato");
      return null;
    }
    log("ERRO", `Frete Barato error ${status}`, { data: err.response?.data, url });
    return null;
  }
}

// ============================================================
// FRETE BARATO — Buscar etiqueta de envio (PDF em base64)
// ============================================================
async function buscarEtiquetaFreteBarato(chaveNF) {
  const url = `${CONFIG.freteBarato.baseUrl}/${CONFIG.freteBarato.plataforma}/etiqueta/v1/json/${CONFIG.freteBarato.customerId}`;
  try {
    const response = await axios.post(url, {
      cnpj: CONFIG.empresa.cnpj,
      nota_fiscal_id: chaveNF,
    }, {
      headers: {
        Authorization: `Bearer ${CONFIG.freteBarato.token}`,
        Accept: "application/json",
        "Content-Type": "application/json",
        "User-Agent": "LAB77-Webhook",
      },
      timeout: 15000,
    });
    const etiqueta = response.data?.etiqueta;
    if (!etiqueta) return null;
    return etiqueta;
  } catch (err) {
    const status = err.response?.status;
    if (status === 404) return null;
    if (err.code === "ECONNABORTED" || err.code === "ETIMEDOUT") {
      log("AVISO", "Timeout Frete Barato (etiqueta)");
      return null;
    }
    log("ERRO", `Frete Barato etiqueta error ${status}`, { data: err.response?.data, url });
    return null;
  }
}

// ============================================================
// BLING — Buscar NF e Gravar tracking (com retry automático em 401)
// ============================================================
async function buscarNFBling(nfeId) {
  try {
    const response = await blingRequest("get", `/nfe/${nfeId}`);
    return response.data?.data || null;
  } catch (err) {
    log("ERRO", `Bling GET /nfe/${nfeId} error ${err.response?.status}`, { data: err.response?.data });
    return null;
  }
}

async function gravarTrackingBling(nfeId, trackCode) {
  const nf = await buscarNFBling(nfeId);
  if (!nf) { log("ERRO", `Não foi possível buscar NF ${nfeId}`); return false; }

  // PUT do Bling exige payload completo — clonar NF inteira e só alterar tracking
  const payload = JSON.parse(JSON.stringify(nf));

  // Remover campos somente-leitura que o Bling rejeita no PUT
  delete payload.id;
  delete payload.situacao;
  delete payload.chaveAcesso;
  delete payload.chave;
  delete payload.linkDanfe;
  delete payload.linkPDF;
  delete payload.xml;

  // Garantir que transporte.volumes existe e adicionar tracking
  if (!payload.transporte) payload.transporte = {};
  if (!payload.transporte.volumes || payload.transporte.volumes.length === 0) {
    payload.transporte.volumes = [{}];
  }
  payload.transporte.volumes[0].codigoRastreamento = trackCode;

  try {
    const response = await blingRequest("put", `/nfe/${nfeId}`, payload);
    return response.status === 200 || response.status === 204;
  } catch (err) {
    log("ERRO", `Bling PUT /nfe/${nfeId} error ${err.response?.status}`, { data: err.response?.data });
    return false;
  }
}

// ============================================================
// PROCESSAMENTO PRINCIPAL
// ============================================================
async function processarNF(nfeId, chaveNF) {
  log("INFO", `Processando NF ${nfeId}`);
  let trackCode = null;
  for (let i = 1; i <= CONFIG.retry.tentativas; i++) {
    log("INFO", `Tentativa ${i}/${CONFIG.retry.tentativas}`);
    trackCode = await buscarTrackingFreteBarato(chaveNF);
    if (trackCode) { log("INFO", `Tracking obtido: ${trackCode}`); break; }
    if (i < CONFIG.retry.tentativas) {
      log("INFO", `Aguardando ${CONFIG.retry.intervaloMs / 1000}s...`);
      await sleep(CONFIG.retry.intervaloMs);
    }
  }
  if (!trackCode) {
    log("AVISO", `Sem tracking após ${CONFIG.retry.tentativas} tentativas — fila`, { nfeId });
    fila.set(chaveNF, { nfeId, tentativas: 0, timestamp: Date.now() });
    return false;
  }
  const sucesso = await gravarTrackingBling(nfeId, trackCode);
  if (sucesso) {
    log("OK", `Tracking gravado no Bling`, { nfeId, trackCode });
    fila.delete(chaveNF);

    // Buscar etiqueta de envio
    try {
      const etiquetaBase64 = await buscarEtiquetaFreteBarato(chaveNF);
      if (etiquetaBase64) {
        etiquetas.set(String(nfeId), etiquetaBase64);
        log("OK", `Etiqueta disponível: /etiqueta/${nfeId}`);
      } else {
        log("AVISO", `Etiqueta não disponível para NF ${nfeId}`);
      }
    } catch (err) {
      log("AVISO", `Erro ao buscar etiqueta NF ${nfeId}`, { error: err.message });
    }

    return true;
  }
  log("ERRO", `Falha ao gravar — fila`, { nfeId });
  fila.set(chaveNF, { nfeId, tentativas: 0, timestamp: Date.now() });
  return false;
}

// ============================================================
// WEBHOOK DO BLING
// ============================================================
app.post("/webhook/bling", rateLimit, (req, res) => {
  if (!verificarAssinaturaBling(req)) return res.status(401).json({ error: "assinatura inválida" });

  const body = req.body;
  if (!body) return res.status(200).json({ ok: true, msg: "body vazio" });

  const situacao = body.situacao ?? body.data?.situacao?.valor ?? body.data?.situacao;
  const nfeId = body.nfeId ?? body.data?.id;
  log("INFO", `Webhook`, { event: body?.event, nfeId, situacao });

  const eventosAceitos = ["invoice.created", "invoice.updated", "nfe.authorized", "nfe.atualizacao", "nfe.update"];
  if (!eventosAceitos.includes(body.event)) {
    return res.status(200).json({ ok: true, msg: `evento ignorado: ${body.event}` });
  }

  if (![6, "6"].includes(situacao)) {
    return res.status(200).json({ ok: true, msg: `situacao ${situacao} ignorada` });
  }

  if (!nfeId) return res.status(400).json({ error: "nfeId ausente" });

  if (emProcessamento.has(nfeId)) {
    return res.status(200).json({ ok: true, msg: "duplicata ignorada" });
  }
  emProcessamento.add(nfeId);
  res.status(200).json({ ok: true, msg: "processando" });

  // Delay 2s — Bling pode não ter preenchido chaveAcesso ainda
  setTimeout(async () => {
    try {
      const nf = await buscarNFBling(nfeId);
      if (!nf) { log("ERRO", `NF ${nfeId} não encontrada`); return; }
      const chaveNF = nf.chaveAcesso || nf.chave;
      if (!chaveNF || !/^\d{44}$/.test(chaveNF)) {
        log("ERRO", `Chave NF inválida`, { nfeId, chaveNF });
        return;
      }
      await processarNF(nfeId, chaveNF);
    } catch (err) {
      log("ERRO", "Erro no webhook", { error: err.message });
    } finally {
      emProcessamento.delete(nfeId);
    }
  }, 2000);
});

// ============================================================
// JOB: Reprocessar fila a cada 10 minutos
// ============================================================
let jobRunning = false;
setInterval(async () => {
  if (fila.size === 0) return;
  if (jobRunning) return;
  jobRunning = true;
  log("INFO", `Reprocessando fila: ${fila.size} NF(s)`);
  try {
    for (const [chaveNF, item] of fila.entries()) {
      item.tentativas++;
      const trackCode = await buscarTrackingFreteBarato(chaveNF);
      if (trackCode) {
        const ok = await gravarTrackingBling(item.nfeId, trackCode);
        if (ok) { log("OK", `Reprocessada: ${item.nfeId}`); fila.delete(chaveNF); }
      }
      if (Date.now() - item.timestamp > 24 * 60 * 60 * 1000) {
        log("AVISO", `Descartada após 24h: ${item.nfeId}`); fila.delete(chaveNF);
      }
    }
  } catch (err) {
    log("ERRO", "Erro no job", { error: err.message });
  } finally {
    jobRunning = false;
  }
}, 10 * 60 * 1000);

// ============================================================
// HEALTH + REPROCESSAMENTO MANUAL
// ============================================================
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    blingToken: tokens.accessToken ? "ativo" : "ausente",
    tokenExpira: tokens.expiresAt ? new Date(tokens.expiresAt).toISOString() : null,
    fila: fila.size,
    uptime: Math.floor(process.uptime()) + "s",
  });
});

app.post("/reprocessar", autenticarApiKey, async (req, res) => {
  const { nfeId, chaveNF } = req.body || {};
  if (!nfeId || !chaveNF) return res.status(400).json({ error: "nfeId e chaveNF obrigatórios" });
  if (!/^\d{44}$/.test(chaveNF)) return res.status(400).json({ error: "chaveNF inválida" });
  res.json({ ok: true, msg: "processando" });
  processarNF(nfeId, chaveNF).catch((err) => log("ERRO", "Reprocessamento erro", { error: err.message }));
});

// ============================================================
// ETIQUETAS DE ENVIO
// ============================================================
app.get("/etiqueta/:nfeId", async (req, res) => {
  const { nfeId } = req.params;

  // Primeiro tenta o cache em memória
  let base64 = etiquetas.get(String(nfeId));

  // Se não tem no cache, busca no Frete Barato
  if (!base64) {
    const nf = await buscarNFBling(Number(nfeId));
    if (!nf) return res.status(404).json({ error: "NF não encontrada no Bling" });

    const chaveNF = nf.chaveAcesso || nf.chave;
    if (!chaveNF) return res.status(404).json({ error: "NF sem chaveAcesso" });

    base64 = await buscarEtiquetaFreteBarato(chaveNF);
    if (!base64) return res.status(404).json({ error: "Etiqueta não disponível no Frete Barato" });

    etiquetas.set(String(nfeId), base64);
  }

  const pdf = Buffer.from(base64, "base64");
  res.set({
    "Content-Type": "application/pdf",
    "Content-Disposition": `inline; filename="etiqueta-${nfeId}.pdf"`,
    "Content-Length": pdf.length,
  });
  res.send(pdf);
});

app.get("/etiquetas", autenticarApiKey, (req, res) => {
  const lista = [];
  for (const nfeId of etiquetas.keys()) {
    lista.push({ nfeId, url: `${CONFIG.servidor.baseUrl}/etiqueta/${nfeId}` });
  }
  res.json({ total: lista.length, etiquetas: lista });
});

// ============================================================
// INICIAR
// ============================================================
const VARS_OBRIGATORIAS = ["BLING_CLIENT_ID", "BLING_CLIENT_SECRET", "FRETEBARATO_TOKEN", "FRETEBARATO_CUSTOMER_ID", "EMPRESA_CNPJ"];
const varsFaltando = VARS_OBRIGATORIAS.filter(v => !process.env[v]);
if (varsFaltando.length > 0) {
  console.error(`[ERRO FATAL] Variáveis não configuradas: ${varsFaltando.join(", ")}`);
  process.exit(1);
}

// Inicializa tokens ANTES de aceitar conexões
inicializarTokens().then(() => {
  const PORT = process.env.PORT || 3000;
  const server = app.listen(PORT, "0.0.0.0", () => {
    log("INFO", `Servidor na porta ${PORT}`);
    if (!tokens.accessToken) {
      log("AVISO", `SEM TOKEN — acesse ${CONFIG.servidor.baseUrl}/authorize`);
    }
  });

  process.on("SIGTERM", () => {
    log("INFO", "SIGTERM — encerrando");
    server.close(() => process.exit(0));
  });
});

module.exports = { app, fila, etiquetas };
