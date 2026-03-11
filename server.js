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
  servidor: { apiKey: process.env.WEBHOOK_API_KEY },
  retry: { tentativas: 6, intervaloMs: 30000 },
};

const fila = new Map();
function sleep(ms) { return new Promise((resolve) => setTimeout(resolve, ms)); }
function log(nivel, mensagem, dados = null) {
  const ts = new Date().toISOString();
  console.log(`[${ts}] [${nivel}] ${mensagem}`);
  if (dados) console.log(JSON.stringify(dados, null, 2));
}

// ============================================================
// TOKEN BLING — Refresh automático
// ============================================================
async function renovarTokenBling() {
  if (!CONFIG.bling.refreshToken || !CONFIG.bling.clientId || !CONFIG.bling.clientSecret) {
    log("AVISO", "Refresh token não configurado — token pode expirar em produção");
    return false;
  }
  try {
    const credentials = Buffer.from(`${CONFIG.bling.clientId}:${CONFIG.bling.clientSecret}`).toString("base64");
    const response = await axios.post(
      "https://www.bling.com.br/Api/v3/oauth/token",
      new URLSearchParams({ grant_type: "refresh_token", refresh_token: CONFIG.bling.refreshToken }),
      {
        headers: { Authorization: `Basic ${credentials}`, "Content-Type": "application/x-www-form-urlencoded" },
        timeout: 10000,
      }
    );
    CONFIG.bling.accessToken = response.data.access_token;
    CONFIG.bling.refreshToken = response.data.refresh_token;
    CONFIG.bling.tokenExpiresAt = Date.now() + 55 * 60 * 1000;
    log("INFO", "Token Bling renovado com sucesso");
    return true;
  } catch (err) {
    log("ERRO", "Falha ao renovar token Bling", { status: err.response?.status });
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
// FRETE BARATO — Buscar tracking
// ============================================================
async function buscarTrackingFreteBarato(chaveNF) {
  const url = `${CONFIG.freteBarato.baseUrl}/${CONFIG.freteBarato.plataforma}/tracking/v1/json/${CONFIG.freteBarato.customerId}`;
  try {
    const response = await axios.get(url, {
      params: { cnpj: CONFIG.empresa.cnpj, nota_fiscal_id: chaveNF },
      headers: { Authorization: `Bearer ${CONFIG.freteBarato.token}`, "User-Agent": "LAB77-Webhook (ti@lab77.com.br)" },
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
    log("ERRO", `Frete Barato error ${status}`);
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

  // Log sem dados sensíveis (LGPD)
  log("INFO", `Webhook recebido`, { event: body?.event, nfeId: body?.data?.id });

  // Bling v3 eventos: nfe.criacao, nfe.atualizacao, nfe.exclusao
  // Bling v3 envia eventos como "invoice.created", "invoice.updated"
  // Situação 9 = Autorizada (confirmado via log de produção)
  // Aceita também situação "A" por compatibilidade
  const situacao = body.data?.situacao?.valor ?? body.data?.situacao;
  const situacaoAutorizada = situacao === 9 || situacao === "9" || situacao === "A";
  const eventosAceitos = [
    "invoice.created",
    "invoice.updated",
    "nfe.authorized",
    "nfe.atualizacao",
    "nfe.update",
  ];

  const deveProcessar = eventosAceitos.includes(body.event) && situacaoAutorizada;

  if (!deveProcessar) {
    log("INFO", `Evento "${body.event}" ignorado (situação: ${situacao})`);
    return res.status(200).json({ ok: true, msg: `evento ignorado: ${body.event}` });
  }

  const nfeId = body.data?.id;
  const chaveNF = body.data?.chave;
  if (!nfeId || !chaveNF) return res.status(400).json({ error: "dados incompletos" });
  if (!/^\d{44}$/.test(chaveNF)) return res.status(400).json({ error: "chave NF inválida" });

  res.status(200).json({ ok: true, msg: "processando" });
  processarNF(nfeId, chaveNF).catch((err) => log("ERRO", "Erro inesperado", { error: err.message }));
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
    fila: fila.size,
    uptime: Math.floor(process.uptime()) + "s",
    timestamp: new Date().toISOString(),
    tokenExpiraEm: new Date(CONFIG.bling.tokenExpiresAt).toISOString(),
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
const VARS_OBRIGATORIAS = ["BLING_ACCESS_TOKEN", "FRETEBARATO_TOKEN", "FRETEBARATO_CUSTOMER_ID", "EMPRESA_CNPJ"];
const varsFaltando = VARS_OBRIGATORIAS.filter(v => !process.env[v]);
if (varsFaltando.length > 0) {
  console.error(`[ERRO FATAL] Variáveis não configuradas: ${varsFaltando.join(", ")}`);
  process.exit(1);
}

const PORT = process.env.PORT || 3000;

// "0.0.0.0" obrigatório para Railway — sem isso o servidor escuta apenas
// em localhost e o proxy externo não consegue rotear o tráfego (502)
const server = app.listen(PORT, "0.0.0.0", () => {
  log("INFO", `Servidor na porta ${PORT} (0.0.0.0)`);
  if (!CONFIG.bling.webhookSecret) log("AVISO", "Configure BLING_WEBHOOK_SECRET!");
  if (!CONFIG.servidor.apiKey)     log("AVISO", "Configure WEBHOOK_API_KEY!");
  if (!CONFIG.bling.refreshToken)  log("AVISO", "Configure BLING_REFRESH_TOKEN para renovação automática!");
});

// Graceful shutdown — Railway envia SIGTERM antes de matar o container
process.on("SIGTERM", () => {
  log("INFO", "SIGTERM recebido — encerrando servidor");
  server.close(() => { log("INFO", "Servidor encerrado"); process.exit(0); });
});

module.exports = { app, fila };
