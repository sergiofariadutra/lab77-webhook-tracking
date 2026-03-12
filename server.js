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
  const payload = { cnpj: CONFIG.empresa.cnpj, nota_fiscal_id: chaveNF };
  log("INFO", `Buscando etiqueta Frete Barato`, { url, payload });
  try {
    const response = await axios.post(url, payload, {
      headers: {
        Authorization: `Bearer ${CONFIG.freteBarato.token}`,
        Accept: "application/json",
        "Content-Type": "application/json",
        "User-Agent": "LAB77-Webhook",
      },
      timeout: 15000,
    });
    log("INFO", `Frete Barato etiqueta response ${response.status}`, {
      keys: Object.keys(response.data || {}),
      temEtiqueta: !!response.data?.etiqueta,
      dataPreview: typeof response.data === "string" ? response.data.substring(0, 200) : undefined,
    });
    const etiqueta = response.data?.etiqueta;
    if (!etiqueta) return null;
    return etiqueta;
  } catch (err) {
    const status = err.response?.status;
    log("ERRO", `Frete Barato etiqueta error ${status}`, {
      payload,
      url,
      responseData: err.response?.data,
      responseHeaders: err.response?.headers,
    });
    if (err.code === "ECONNABORTED" || err.code === "ETIMEDOUT") {
      log("AVISO", "Timeout Frete Barato (etiqueta)");
    }
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
  // NFs autorizadas são read-only no Bling
  // Estratégia: buscar NF → encontrar pedido vinculado → gravar tracking no pedido
  const nf = await buscarNFBling(nfeId);
  if (!nf) { log("ERRO", `Não foi possível buscar NF ${nfeId}`); return false; }

  // Log das chaves da NF para debug (ajuda a encontrar a referência ao pedido)
  log("INFO", `NF ${nfeId} keys: ${Object.keys(nf).join(", ")}`);

  // Tentar encontrar o pedido de venda em vários caminhos possíveis
  const pedidoId = nf.pedidoVenda?.id
    || nf.pedido?.id
    || nf.vendas?.id
    || nf.pedidosVenda?.[0]?.id
    || nf.contato?.pedidoVenda?.id;

  if (pedidoId) {
    try {
      const response = await blingRequest("put", `/pedidos/vendas/${pedidoId}`, {
        transporte: {
          volumes: [{ codigoRastreamento: trackCode }],
        },
      });
      log("OK", `Tracking gravado no pedido ${pedidoId}`, { nfeId, trackCode });
      return response.status === 200 || response.status === 204;
    } catch (err) {
      log("ERRO", `PUT /pedidos/vendas/${pedidoId} error ${err.response?.status}`, { data: err.response?.data });
    }
  } else {
    log("AVISO", `NF ${nfeId} sem pedido vinculado — tentando POST /logisticas/objetos`);
  }

  // Fallback: criar objeto logístico (funciona sem pedido de venda)
  try {
    const response = await blingRequest("post", `/logisticas/objetos`, {
      notaFiscal: { id: nfeId },
      rastreamento: {
        codigo: trackCode,
        descricao: "Rastreamento automático",
        situacao: 5, // 5 = Em aberto
      },
    });
    log("OK", `Objeto logístico criado para NF ${nfeId}`, { trackCode, objetoId: response.data?.data?.id });
    return true;
  } catch (err) {
    log("ERRO", `POST /logisticas/objetos error ${err.response?.status}`, { data: err.response?.data });
  }

  return false;
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
// API PROXY — Para Google Sheets / Apps Script
// ============================================================

// Buscar NF pelo número do pedido Shopify
app.get("/api/nf-por-pedido", autenticarApiKey, async (req, res) => {
  const numeroPedido = req.query.numeroPedido;
  if (!numeroPedido) return res.status(400).json({ error: "numeroPedido obrigatório" });

  try {
    // Busca NF no Bling pelo número do pedido Shopify (campo numeroLoja)
    // Tenta situacao 6 (Emitida DANFE) primeiro, depois 5 (Autorizada)
    let nf = null;
    for (const sit of [6, 5]) {
      const response = await blingRequest("get", `/nfe?numeroLoja=${encodeURIComponent(numeroPedido)}&tipo=1&situacao=${sit}&limite=1`);
      const dados = response.data?.data || [];
      if (dados.length > 0) { nf = dados[0]; break; }
    }

    if (!nf) {
      // Tenta sem filtro de situação (NF pode estar pendente ainda)
      const response = await blingRequest("get", `/nfe?numeroLoja=${encodeURIComponent(numeroPedido)}&tipo=1&limite=1`);
      const dados = response.data?.data || [];
      if (dados.length > 0) nf = dados[0];
    }

    if (!nf) return res.status(404).json({ error: "NF não encontrada para este pedido" });

    const nfeId = nf.id;
    const situacao = nf.situacao;
    const situacaoNome = { 1: "Pendente", 2: "Cancelada", 3: "Aguardando recibo", 4: "Rejeitada", 5: "Autorizada", 6: "Emitida DANFE", 7: "Registrada" }[situacao] || `Desconhecida (${situacao})`;

    res.json({
      nfeId,
      numero: nf.numero,
      situacao,
      situacaoNome,
      contato: nf.contato?.nome || null,
      valorNota: nf.valorNota || nf.total || null,
      etiquetaUrl: `${CONFIG.servidor.baseUrl}/etiqueta/${nfeId}`,
    });
  } catch (err) {
    log("ERRO", "API nf-por-pedido erro", { error: err.message, status: err.response?.status });
    res.status(500).json({ error: "Erro ao consultar Bling", detalhes: err.response?.data || err.message });
  }
});

// Emitir (autorizar) NF no Bling
app.post("/api/emitir-nf", autenticarApiKey, async (req, res) => {
  const { numeroPedido, nfeId } = req.body || {};

  try {
    let id = nfeId;

    // Se não passou nfeId, busca pelo número do pedido
    if (!id && numeroPedido) {
      const response = await blingRequest("get", `/nfe?numeroLoja=${encodeURIComponent(numeroPedido)}&tipo=1&limite=1`);
      const dados = response.data?.data || [];
      if (dados.length === 0) return res.status(404).json({ error: "NF não encontrada para este pedido" });
      id = dados[0].id;
    }

    if (!id) return res.status(400).json({ error: "numeroPedido ou nfeId obrigatório" });

    // Verificar situação atual
    const nfResponse = await blingRequest("get", `/nfe/${id}`);
    const nf = nfResponse.data?.data;
    if (!nf) return res.status(404).json({ error: "NF não encontrada" });

    if ([5, 6].includes(nf.situacao)) {
      return res.json({
        ok: true,
        msg: "NF já autorizada",
        nfeId: id,
        situacao: nf.situacao,
        etiquetaUrl: `${CONFIG.servidor.baseUrl}/etiqueta/${id}`,
      });
    }

    // Enviar NF para autorização na SEFAZ
    await blingRequest("post", `/nfe/${id}/enviar`);
    log("OK", `NF ${id} enviada para autorização`, { numeroPedido });

    res.json({
      ok: true,
      msg: "NF enviada para autorização na SEFAZ. Aguarde o webhook processar a etiqueta.",
      nfeId: id,
      etiquetaUrl: `${CONFIG.servidor.baseUrl}/etiqueta/${id}`,
    });
  } catch (err) {
    log("ERRO", "API emitir-nf erro", { error: err.message, status: err.response?.status, data: err.response?.data });
    res.status(500).json({ error: "Erro ao emitir NF", detalhes: err.response?.data || err.message });
  }
});

// ============================================================
// PAINEL — Dashboard de NFs autorizadas
// ============================================================
app.get("/painel", async (req, res) => {
  let nfsHtml = "";
  let erro = "";

  try {
    // Buscar NFs autorizadas — situacao 5 e 6 (Autorizada + Emitida DANFE)
    // Filtra por data de emissão para pegar as mais recentes
    const nfs = [];
    const MAX_PAGINAS = 10; // até 1000 NFs por situação

    for (const sit of [6, 5]) {
      for (let pagina = 1; pagina <= MAX_PAGINAS; pagina++) {
        const response = await blingRequest("get", `/nfe?situacao=${sit}&limite=100&pagina=${pagina}`);
        const dados = response.data?.data || [];
        nfs.push(...dados);
        log("INFO", `Painel: situacao=${sit} página ${pagina} → ${dados.length} NFs`);
        if (dados.length < 100) break; // última página
      }
    }

    // Ordenar por número decrescente (mais recentes primeiro)
    nfs.sort((a, b) => (b.numero || b.id || 0) - (a.numero || a.id || 0));
    log("INFO", `Painel: total ${nfs.length} NFs carregadas`);

    if (nfs.length === 0) {
      nfsHtml = `<tr><td colspan="4" style="text-align:center;padding:20px;color:#888">Nenhuma NF autorizada encontrada</td></tr>`;
    } else {
      for (const nf of nfs) {
        const numero = nf.numero || nf.id || "—";
        const nome = nf.contato?.nome || nf.cliente?.nome || "—";
        const valor = nf.valorNota != null
          ? `R$ ${Number(nf.valorNota).toFixed(2)}`
          : (nf.total != null ? `R$ ${Number(nf.total).toFixed(2)}` : "—");
        const nfeId = nf.id;

        nfsHtml += `<tr>
          <td>${numero}</td>
          <td>${nome}</td>
          <td>${valor}</td>
          <td><a href="/etiqueta/${nfeId}" target="_blank" style="color:#0f0;text-decoration:none">&#x1F5A8; Imprimir</a></td>
        </tr>`;
      }
    }
  } catch (err) {
    const msg = err.response?.data?.error?.message || err.message || "Erro desconhecido";
    log("ERRO", "Painel: erro ao buscar NFs", { error: msg, status: err.response?.status });
    erro = `<div style="color:#f55;padding:20px;text-align:center">Erro ao buscar NFs: ${msg}</div>`;
  }

  const totalNfs = nfsHtml ? nfsHtml.split("</tr>").length - 1 : 0;

  res.send(`<!DOCTYPE html>
<html><head>
  <meta charset="utf-8">
  <title>LAB77 — Painel de Etiquetas</title>
  <meta http-equiv="refresh" content="60">
  <style>
    body { font-family: monospace; background: #1a1a2e; color: #e0e0e0; margin: 0; padding: 20px; }
    h1 { color: #0f0; margin: 0 0 5px 0; }
    .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; border-bottom: 1px solid #333; padding-bottom: 15px; }
    .btn { background: #0f0; color: #000; border: none; padding: 8px 16px; font-family: monospace; font-weight: bold; cursor: pointer; }
    .btn:hover { background: #0a0; }
    table { width: 100%; border-collapse: collapse; }
    th { text-align: left; padding: 10px; border-bottom: 2px solid #0f0; color: #0f0; cursor: pointer; }
    td { padding: 10px; border-bottom: 1px solid #333; }
    tr:hover { background: #222244; }
    .sub { color: #888; font-size: 0.85em; }
    .busca { background: #111; border: 1px solid #0f0; color: #0f0; padding: 8px 12px; font-family: monospace; width: 250px; margin-right: 10px; }
    .paginacao { display: flex; gap: 8px; align-items: center; margin-top: 15px; justify-content: center; }
    .paginacao button { background: #333; color: #0f0; border: 1px solid #0f0; padding: 5px 12px; font-family: monospace; cursor: pointer; }
    .paginacao button:hover { background: #0f0; color: #000; }
    .paginacao button.ativo { background: #0f0; color: #000; }
    .paginacao button:disabled { opacity: 0.3; cursor: default; }
    .info { color: #888; font-size: 0.85em; margin-top: 10px; text-align: center; }
  </style>
</head><body>
  <div class="header">
    <div>
      <h1>LAB77 — Painel de Etiquetas</h1>
      <span class="sub">Total: ${totalNfs} NFs | Auto-refresh: 60s | ${new Date().toLocaleString("pt-BR", { timeZone: "America/Sao_Paulo" })}</span>
    </div>
    <div>
      <input type="text" class="busca" id="busca" placeholder="Buscar NF ou nome..." oninput="filtrar()">
      <button class="btn" onclick="location.reload()">Atualizar</button>
    </div>
  </div>
  ${erro}
  <table>
    <thead><tr><th>Número NF</th><th>Nome</th><th>Valor</th><th>Etiqueta</th></tr></thead>
    <tbody id="tabela">${nfsHtml}</tbody>
  </table>
  <div class="paginacao" id="paginacao"></div>
  <div class="info" id="info"></div>

  <script>
    const POR_PAGINA = 50;
    let paginaAtual = 1;
    const linhas = Array.from(document.querySelectorAll('#tabela tr'));
    let linhasFiltradas = linhas;

    function filtrar() {
      const termo = document.getElementById('busca').value.toLowerCase();
      linhasFiltradas = linhas.filter(tr => tr.textContent.toLowerCase().includes(termo));
      paginaAtual = 1;
      renderizar();
    }

    function renderizar() {
      const total = linhasFiltradas.length;
      const totalPaginas = Math.ceil(total / POR_PAGINA) || 1;
      if (paginaAtual > totalPaginas) paginaAtual = totalPaginas;

      const inicio = (paginaAtual - 1) * POR_PAGINA;
      const fim = inicio + POR_PAGINA;

      linhas.forEach(tr => tr.style.display = 'none');
      linhasFiltradas.slice(inicio, fim).forEach(tr => tr.style.display = '');

      // Paginação
      const pag = document.getElementById('paginacao');
      let html = '';
      html += '<button ' + (paginaAtual <= 1 ? 'disabled' : '') + ' onclick="ir(' + (paginaAtual-1) + ')">← Anterior</button>';
      for (let i = 1; i <= totalPaginas; i++) {
        if (totalPaginas > 10 && Math.abs(i - paginaAtual) > 2 && i !== 1 && i !== totalPaginas) {
          if (i === 2 || i === totalPaginas - 1) html += '<span style="color:#888">...</span>';
          continue;
        }
        html += '<button class="' + (i === paginaAtual ? 'ativo' : '') + '" onclick="ir(' + i + ')">' + i + '</button>';
      }
      html += '<button ' + (paginaAtual >= totalPaginas ? 'disabled' : '') + ' onclick="ir(' + (paginaAtual+1) + ')">Próxima →</button>';
      pag.innerHTML = html;

      document.getElementById('info').textContent = 'Mostrando ' + (inicio+1) + '-' + Math.min(fim, total) + ' de ' + total + ' NFs';
    }

    function ir(p) { paginaAtual = p; renderizar(); }

    renderizar();
  </script>
</body></html>`);
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
