/**
 * LAB77 / GRUPO 77
 * Webhook: Frete Barato → Bling
 * v3.0 — Revisão completa por painel de especialistas
 *
 * Correções Rodada 1:
 *  [CRÍTICO] app.listen sem "0.0.0.0" causava 502 no Railway
 *  [CRÍTICO] PUT enviava payload completo — agora envia só { transporte }
 *  [CRÍTICO] Token Bling renovado automaticamente via refresh_token
 *  [IMPORTANTE] Evento nfe.atualizacao adicionado à lista de aceitos
 *  [IMPORTANTE] SIGTERM tratado para graceful shutdown
 *  [IMPORTANTE] Log DEBUG removido — não vaza dados sensíveis (LGPD)
 *  [IMPORTANTE] ETIMEDOUT capturado junto com ECONNABORTED
 *  [IMPORTANTE] Rate limiting básico no endpoint webhook
 */

require("dotenv").config();
const express = require("express");
const axios = require("axios");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();

// Raw body necessário para verificar assinatura HMAC do Bling
app.use(express.json({
  verify: (req, res, buf) => { req.rawBody = buf; }
}));

// Rate limiting simples sem dependência externa
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
    accessToken: process.env.BLING_ACCESS_TOKEN,
    refreshToken: process.env.BLING_REFRESH_TOKEN,
    clientId: process.env.BLING_CLIENT_ID,
    clientSecret: process.env.BLING_CLIENT_SECRET,
    baseUrl: "https://www.bling.com.br/Api/v3",
    webhookSecret: process.env.BLING_WEBHOOK_SECRET,
    tokenExpiresAt: Date.now() + 55 * 60 * 1000,
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
const emProcessamento = new Set(); // deduplicação de webhooks simultâneos
function sleep(ms) { return new Promise((resolve) => setTimeout(resolve, ms)); }
function log(nivel, mensagem, dados = null) {
  const ts = new Date().toISOString();
  console.log(`[${ts}] [${nivel}] ${mensagem}`);
  if (dados) console.log(JSON.stringify(dados, null, 2));
}

// ============================================================
// PERSISTÊNCIA DE TOKENS BLING (sobrevive a restarts)
// ============================================================
const TOKEN_FILE = path.join(__dirname, ".bling-tokens.json");

function salvarTokens() {
  try {
    fs.writeFileSync(TOKEN_FILE, JSON.stringify({
      accessToken: CONFIG.bling.accessToken,
      refreshToken: CONFIG.bling.refreshToken,
      expiresAt: CONFIG.bling.tokenExpiresAt,
    }, null, 2));
    log("INFO", "Tokens salvos em disco");
  } catch (err) {
    log("AVISO", "Falha ao salvar tokens em disco", { error: err.message });
  }
}

function carregarTokens() {
  // Tenta carregar do arquivo (persiste entre restarts sem redeploy)
  try {
    if (fs.existsSync(TOKEN_FILE)) {
      const data = JSON.parse(fs.readFileSync(TOKEN_FILE, "utf-8"));
      if (data.accessToken) CONFIG.bling.accessToken = data.accessToken;
      if (data.refreshToken) CONFIG.bling.refreshToken = data.refreshToken;
      if (data.expiresAt) CONFIG.bling.tokenExpiresAt = data.expiresAt;
      log("INFO", "Tokens carregados do disco", {
        temAccessToken: !!data.accessToken,
        temRefreshToken: !!data.refreshToken,
        expiraEm: new Date(data.expiresAt).toISOString(),
      });
      return;
    }
  } catch (err) {
    log("AVISO", "Sem tokens salvos em disco");
  }

  // Fallback: se tem refresh_token na env var, faz refresh imediato
  if (CONFIG.bling.refreshToken && CONFIG.bling.clientId && CONFIG.bling.clientSecret) {
    log("INFO", "Sem arquivo de tokens — tentando refresh via BLING_REFRESH_TOKEN env var...");
    renovarTokenBling().then((ok) => {
      if (ok) log("OK", "Token obtido via env var no startup");
      else log("ERRO", "Refresh via env var falhou — acesse /authorize para re-autorizar");
    });
  }
}

function basicAuthHeader() {
  return "Basic " + Buffer.from(`${CONFIG.bling.clientId}:${CONFIG.bling.clientSecret}`).toString("base64");
}

// ============================================================
// TOKEN BLING — Refresh automático
// ============================================================
async function renovarTokenBling() {
  if (!CONFIG.bling.refreshToken || !CONFIG.bling.clientId || !CONFIG.bling.clientSecret) {
    log("AVISO", "Refresh token não configurado — faça OAuth via /oauth/callback");
    return false;
  }
  try {
    const response = await axios.post(
      "https://www.bling.com.br/Api/v3/oauth/token",
      new URLSearchParams({ grant_type: "refresh_token", refresh_token: CONFIG.bling.refreshToken }),
      {
        headers: { Authorization: basicAuthHeader(), "Content-Type": "application/x-www-form-urlencoded" },
        timeout: 10000,
      }
    );
    CONFIG.bling.accessToken = response.data.access_token;
    CONFIG.bling.refreshToken = response.data.refresh_token;
    CONFIG.bling.tokenExpiresAt = Date.now() + 55 * 60 * 1000;
    salvarTokens();
    log("INFO", "Token Bling renovado com sucesso");
    return true;
  } catch (err) {
    log("ERRO", "Falha ao renovar token Bling", { status: err.response?.status, data: err.response?.data });
    return false;
  }
}

async function garantirTokenValido() {
  if (Date.now() >= CONFIG.bling.tokenExpiresAt) {
    log("INFO", "Token Bling expirado — renovando...");
    await renovarTokenBling();
  }
}

// ============================================================
// VERIFICAÇÃO DE ASSINATURA DO BLING (HMAC-SHA256)
// ============================================================
function verificarAssinaturaBling(req) {
  if (!CONFIG.bling.webhookSecret) {
    log("AVISO", "BLING_WEBHOOK_SECRET não configurado — webhook sem autenticação!");
    return true;
  }
  const assinatura = req.headers["x-bling-signature"] || req.headers["x-signature"];
  if (!assinatura) { log("ERRO", "Webhook sem assinatura — rejeitado"); return false; }
  const hmac = crypto.createHmac("sha256", CONFIG.bling.webhookSecret).update(req.rawBody).digest("hex");
  try {
    const assinaturaEsperada = `sha256=${hmac}`;
    if (assinatura.length !== assinaturaEsperada.length) return false;
    return crypto.timingSafeEqual(Buffer.from(assinatura), Buffer.from(assinaturaEsperada));
  } catch { return false; }
}

function autenticarApiKey(req, res, next) {
  if (!CONFIG.servidor.apiKey) { log("AVISO", "WEBHOOK_API_KEY não configurado!"); return next(); }
  const key = req.headers["x-api-key"];
  if (!key || key !== CONFIG.servidor.apiKey) return res.status(401).json({ error: "não autorizado" });
  next();
}

// ============================================================
// BLING OAuth2 — Rotas /oauth/callback e /authorize
// ============================================================
app.get("/oauth/callback", async (req, res) => {
  const { code } = req.query;
  if (!code) return res.status(400).json({ error: "Parâmetro 'code' ausente" });

  try {
    const response = await axios.post(
      "https://www.bling.com.br/Api/v3/oauth/token",
      new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: `${CONFIG.servidor.baseUrl}/oauth/callback`,
      }),
      {
        headers: { Authorization: basicAuthHeader(), "Content-Type": "application/x-www-form-urlencoded" },
        timeout: 15000,
      }
    );

    CONFIG.bling.accessToken = response.data.access_token;
    CONFIG.bling.refreshToken = response.data.refresh_token;
    CONFIG.bling.tokenExpiresAt = Date.now() + (response.data.expires_in * 1000) - 60000;
    salvarTokens();
    log("OK", "OAuth concluído — tokens obtidos e salvos", { expires_in: response.data.expires_in });

    res.json({
      ok: true,
      msg: "OAuth concluído! Tokens salvos. O webhook está pronto.",
      refresh_token: CONFIG.bling.refreshToken,
      expiraEm: new Date(CONFIG.bling.tokenExpiresAt).toISOString(),
    });
  } catch (err) {
    log("ERRO", "Falha no OAuth callback", { error: err.message, data: err.response?.data });
    res.status(500).json({ error: "Falha ao obter tokens", detalhes: err.response?.data || err.message });
  }
});

app.get("/authorize", (req, res) => {
  const authUrl = `https://www.bling.com.br/Api/v3/oauth/authorize`
    + `?response_type=code`
    + `&client_id=${CONFIG.bling.clientId}`
    + `&state=lab77`;
  res.json({ msg: "Acesse a URL abaixo no navegador para autorizar o app:", url: authUrl });
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
        "User-Agent": "LAB77-Webhook (ti@lab77.com.br)",
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
      log("AVISO", "Timeout Frete Barato — próxima tentativa");
      return null;
    }
    log("ERRO", `Frete Barato error ${status}`, {
      data: err.response?.data,
      headers: err.response?.headers,
      url,
    });
    return null;
  }
}

// ============================================================
// BLING — Buscar NF completa
// ============================================================
async function buscarNFBling(nfeId) {
  await garantirTokenValido();
  const url = `${CONFIG.bling.baseUrl}/nfe/${nfeId}`;
  try {
    const response = await axios.get(url, {
      headers: { Authorization: `Bearer ${CONFIG.bling.accessToken}` },
      timeout: 10000,
    });
    return response.data?.data || null;
  } catch (err) {
    const status = err.response?.status;
    if (status === 401) { log("ERRO", "Token Bling expirado — tentando renovar"); await renovarTokenBling(); }
    log("ERRO", `Bling GET error ${status}`, { nfeId });
    return null;
  }
}

// ============================================================
// BLING — Gravar tracking na NF
// Envia APENAS { transporte } — NFs autorizadas têm campos somente leitura
// que causam 422 se o payload completo for enviado.
// ============================================================
async function gravarTrackingBling(nfeId, trackCode) {
  await garantirTokenValido();
  const nf = await buscarNFBling(nfeId);
  if (!nf) { log("ERRO", `Não foi possível buscar NF ${nfeId}`); return false; }

  // Clona apenas transporte — evita mutação e campos somente leitura
  const transporte = JSON.parse(JSON.stringify(nf.transporte || {}));
  if (!transporte.volumes || transporte.volumes.length === 0) transporte.volumes = [{}];
  transporte.volumes[0].codigoRastreamento = trackCode;

  const url = `${CONFIG.bling.baseUrl}/nfe/${nfeId}`;
  try {
    const response = await axios.put(url, { transporte }, {
      headers: { Authorization: `Bearer ${CONFIG.bling.accessToken}`, "Content-Type": "application/json" },
      timeout: 10000,
    });
    return response.status === 200 || response.status === 204;
  } catch (err) {
    const status = err.response?.status;
    if (status === 401) log("ERRO", "Token Bling expirado");
    log("ERRO", `Bling PUT error ${status}`, { nfeId, trackCode });
    return false;
  }
}

// ============================================================
// PROCESSAMENTO PRINCIPAL
// ============================================================
async function processarNF(nfeId, chaveNF) {
  log("INFO", `Iniciando NF`, { nfeId, chave: chaveNF.substring(0, 10) + "..." });
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
  if (sucesso) { log("OK", `Tracking gravado no Bling`, { nfeId, trackCode }); fila.delete(chaveNF); return true; }
  log("ERRO", `Falha ao gravar no Bling — NF vai para fila`, { nfeId });
  fila.set(chaveNF, { nfeId, tentativas: 0, timestamp: Date.now() });
  return false;
}

// ============================================================
// WEBHOOK DO BLING
// ============================================================
app.post("/webhook/bling", rateLimit, (req, res) => {
  if (!verificarAssinaturaBling(req)) return res.status(401).json({ error: "assinatura inválida" });

  const body = req.body;
  if (!body) return res.status(200).json({ ok: true, msg: "body vazio ignorado" });

  // Bling envia body flat: { event, nfeId, situacao } — sem wrapper "data"
  const situacao = body.situacao ?? body.data?.situacao?.valor ?? body.data?.situacao;
  const nfeId = body.nfeId ?? body.data?.id;
  log("INFO", `Webhook recebido`, { event: body?.event, nfeId, situacao });

  const eventosAceitos = [
    "invoice.created",
    "invoice.updated",
    "nfe.authorized",
    "nfe.atualizacao",
    "nfe.update",
  ];

  if (!eventosAceitos.includes(body.event)) {
    log("INFO", `Evento "${body.event}" ignorado`);
    return res.status(200).json({ ok: true, msg: `evento ignorado: ${body.event}` });
  }

  // Só processa situação 6 (Autorizada) — evita chamadas desnecessárias ao Frete Barato
  // para NFs ainda pendentes (situação 1) ou em processamento (situação 7/8)
  const situacoesProcessaveis = [6, "6"];
  if (!situacoesProcessaveis.includes(situacao)) {
    log("INFO", `Situação ${situacao} ignorada — aguardando autorização`);
    return res.status(200).json({ ok: true, msg: `situacao ${situacao} ignorada` });
  }

  if (!nfeId) return res.status(400).json({ error: "nfeId ausente" });

  // Deduplicação — evita processar a mesma NF duas vezes se o Bling disparar webhooks duplicados
  if (emProcessamento.has(nfeId)) {
    log("INFO", `NF ${nfeId} já em processamento — ignorando duplicata`);
    return res.status(200).json({ ok: true, msg: "duplicata ignorada" });
  }
  emProcessamento.add(nfeId);

  res.status(200).json({ ok: true, msg: "processando" });

  // Delay de 2s antes do GET — garante que o Bling já preencheu chaveAcesso
  // após a autorização da SEFAZ (evita race condition)
  setTimeout(async () => {
    try {
      const nf = await buscarNFBling(nfeId);
      if (!nf) { log("ERRO", `NF ${nfeId} não encontrada na API do Bling`); emProcessamento.delete(nfeId); return; }
      const chaveNF = nf.chaveAcesso || nf.chave;
      if (!chaveNF || !/^\d{44}$/.test(chaveNF)) {
        log("ERRO", `Chave NF inválida ou ausente`, { nfeId, chaveNF });
        emProcessamento.delete(nfeId);
        return;
      }
      await processarNF(nfeId, chaveNF);
    } catch (err) {
      log("ERRO", "Erro inesperado no webhook", { error: err.message });
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
  if (jobRunning) { log("AVISO", "Job ainda rodando — pulando ciclo"); return; }
  jobRunning = true;
  log("INFO", `Reprocessamento fila: ${fila.size} NF(s)`);
  try {
    for (const [chaveNF, item] of fila.entries()) {
      item.tentativas++;
      const trackCode = await buscarTrackingFreteBarato(chaveNF);
      if (trackCode) {
        const ok = await gravarTrackingBling(item.nfeId, trackCode);
        if (ok) { log("OK", `Reprocessada`); fila.delete(chaveNF); }
      }
      if (Date.now() - item.timestamp > 24 * 60 * 60 * 1000) {
        log("AVISO", `Descartada após 24h`); fila.delete(chaveNF);
      }
    }
  } catch (err) {
    log("ERRO", "Erro no job", { error: err.message });
  } finally {
    jobRunning = false;
  }
}, 10 * 60 * 1000);

// ============================================================
// HEALTH CHECK
// ============================================================
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    blingToken: CONFIG.bling.accessToken ? "ativo" : "ausente",
    tokenExpiraEm: new Date(CONFIG.bling.tokenExpiresAt).toISOString(),
    fila: fila.size,
    uptime: Math.floor(process.uptime()) + "s",
    timestamp: new Date().toISOString(),
  });
});

// ============================================================
// REPROCESSAMENTO MANUAL
// ============================================================
app.post("/reprocessar", autenticarApiKey, async (req, res) => {
  const { nfeId, chaveNF } = req.body || {};
  if (!nfeId || !chaveNF) return res.status(400).json({ error: "nfeId e chaveNF obrigatórios" });
  if (!/^\d{44}$/.test(chaveNF)) return res.status(400).json({ error: "chaveNF inválida" });
  res.json({ ok: true, msg: "processando" });
  processarNF(nfeId, chaveNF)
    .then((ok) => log("INFO", `Reprocessamento manual: ${ok ? "OK" : "FALHOU"}`))
    .catch((err) => log("ERRO", "Reprocessamento manual erro", { error: err.message }));
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

// Carregar tokens salvos (se existirem) antes de iniciar
carregarTokens();

const PORT = process.env.PORT || 3000;

// "0.0.0.0" obrigatório para Railway — sem isso o servidor escuta apenas
// em localhost e o proxy externo não consegue rotear o tráfego (502)
const server = app.listen(PORT, "0.0.0.0", () => {
  log("INFO", `Servidor na porta ${PORT} (0.0.0.0)`);
  log("INFO", `OAuth callback: ${CONFIG.servidor.baseUrl}/oauth/callback`);
  if (!CONFIG.bling.accessToken) {
    log("AVISO", `Sem token Bling — acesse ${CONFIG.servidor.baseUrl}/authorize para autorizar`);
  }
  if (!CONFIG.bling.webhookSecret) log("AVISO", "Configure BLING_WEBHOOK_SECRET!");
  if (!CONFIG.servidor.apiKey)     log("AVISO", "Configure WEBHOOK_API_KEY!");
});

// Graceful shutdown — Railway envia SIGTERM antes de matar o container
process.on("SIGTERM", () => {
  log("INFO", "SIGTERM recebido — encerrando servidor");
  server.close(() => { log("INFO", "Servidor encerrado"); process.exit(0); });
});

module.exports = { app, fila };
