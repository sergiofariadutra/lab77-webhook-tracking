/**
 * LAB77 / GRUPO 77
 * Webhook: Frete Barato → Bling
 * v2.1 — Correção endpoint Bling
 *
 * Correções aplicadas:
 *  - PUT /nfe/{id}/rastreamentos NÃO EXISTE no Bling v3
 *  - Novo fluxo: GET /nfe/{id} → inserir codigoRastreamento → PUT /nfe/{id}
 *  - Campo correto: transporte.volumes[0].codigoRastreamento
 *  - GET com params em vez de body (compatibilidade garantida)
 *  - Verificação de assinatura HMAC do Bling
 *  - /reprocessar protegido por API key
 *  - Timeout em todas as chamadas de API
 *  - Logs de produção completos
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

// ============================================================
// CONFIGURAÇÕES
// ============================================================
const CONFIG = {
  bling: {
    accessToken: process.env.BLING_ACCESS_TOKEN,
    baseUrl: "https://www.bling.com.br/Api/v3",
    webhookSecret: process.env.BLING_WEBHOOK_SECRET,
  },
  freteBarato: {
    token: process.env.FRETEBARATO_TOKEN,
    customerId: process.env.FRETEBARATO_CUSTOMER_ID,
    plataforma: process.env.FRETEBARATO_PLATAFORMA || "bling",
    baseUrl: "https://admin.fretebarato.com",
  },
  empresa: {
    cnpj: process.env.EMPRESA_CNPJ,
  },
  servidor: {
    apiKey: process.env.WEBHOOK_API_KEY,
  },
  retry: {
    tentativas: 6,
    intervaloMs: 30000,
  },
};

// Fila em memória (dados perdidos em restart — aceitável para volume LAB77)
const fila = new Map();

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function log(nivel, mensagem, dados = null) {
  const ts = new Date().toISOString();
  console.log(`[${ts}] [${nivel}] ${mensagem}`);
  if (dados) console.log(JSON.stringify(dados, null, 2));
}

// ============================================================
// VERIFICAÇÃO DE ASSINATURA DO BLING (HMAC-SHA256)
// Sem isso, qualquer um que souber a URL pode disparar processamento
// ============================================================
function verificarAssinaturaBling(req) {
  if (!CONFIG.bling.webhookSecret) {
    log("AVISO", "BLING_WEBHOOK_SECRET não configurado — webhook sem autenticação!");
    return true;
  }

  const assinatura = req.headers["x-bling-signature"] || req.headers["x-signature"];
  if (!assinatura) {
    log("ERRO", "Webhook sem assinatura — rejeitado");
    return false;
  }

  const hmac = crypto
    .createHmac("sha256", CONFIG.bling.webhookSecret)
    .update(req.rawBody)
    .digest("hex");

  try {
    const assinaturaEsperada = `sha256=${hmac}`;
    // timingSafeEqual exige buffers do MESMO tamanho — checar antes para não crashar
    if (assinatura.length !== assinaturaEsperada.length) return false;
    return crypto.timingSafeEqual(
      Buffer.from(assinatura),
      Buffer.from(assinaturaEsperada)
    );
  } catch {
    return false;
  }
}

// Protege /reprocessar com API key
function autenticarApiKey(req, res, next) {
  if (!CONFIG.servidor.apiKey) {
    log("AVISO", "WEBHOOK_API_KEY não configurado — /reprocessar sem proteção!");
    return next();
  }
  const key = req.headers["x-api-key"];
  if (!key || key !== CONFIG.servidor.apiKey) {
    return res.status(401).json({ error: "não autorizado" });
  }
  next();
}

// ============================================================
// FRETE BARATO — Buscar tracking
// Usando query params (mais compatível que body em GET)
// ============================================================
async function buscarTrackingFreteBararato(chaveNF) {
  const url = `${CONFIG.freteBarato.baseUrl}/${CONFIG.freteBarato.plataforma}/tracking/v1/json/${CONFIG.freteBarato.customerId}`;

  try {
    const response = await axios.get(url, {
      params: {
        cnpj: CONFIG.empresa.cnpj,
        nota_fiscal_id: chaveNF,
      },
      headers: {
        Authorization: `Bearer ${CONFIG.freteBarato.token}`,
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
    if (err.code === "ECONNABORTED") {
      log("AVISO", "Timeout Frete Barato — próxima tentativa");
      return null;
    }
    log("ERRO", `Frete Barato error ${status}`, err.response?.data);
    return null;
  }
}

// ============================================================
// BLING — Buscar NF completa
// PUT /nfe/{id}/rastreamentos NÃO EXISTE no Bling v3.
// Fluxo correto: GET para buscar, PUT para gravar com payload completo.
// ============================================================
async function buscarNFBling(nfeId) {
  const url = `${CONFIG.bling.baseUrl}/nfe/${nfeId}`;
  try {
    const response = await axios.get(url, {
      headers: {
        Authorization: `Bearer ${CONFIG.bling.accessToken}`,
      },
      timeout: 10000,
    });
    return response.data?.data || null;
  } catch (err) {
    const status = err.response?.status;
    if (status === 401) log("ERRO", "Token Bling expirado — renovar BLING_ACCESS_TOKEN");
    log("ERRO", `Bling GET error ${status}`, { nfeId, data: err.response?.data });
    return null;
  }
}

// ============================================================
// BLING — Gravar tracking na NF
// ATENÇÃO: access_token OAuth2 expira em 1h — implementar refresh se necessário
//
// Bling v3 NÃO TEM PUT /nfe/{id}/rastreamentos.
// O campo correto é: transporte.volumes[0].codigoRastreamento
// Fluxo: GET NF → inserir codigoRastreamento → PUT NF completa
// ============================================================
async function gravarTrackingBling(nfeId, trackCode) {
  // 1. Buscar NF completa
  const nf = await buscarNFBling(nfeId);
  if (!nf) {
    log("ERRO", `Não foi possível buscar NF ${nfeId} no Bling`);
    return false;
  }

  // 2. Inserir codigoRastreamento no primeiro volume do transporte
  // Se não tiver volumes, cria estrutura mínima
  if (!nf.transporte) nf.transporte = {};
  if (!nf.transporte.volumes || nf.transporte.volumes.length === 0) {
    nf.transporte.volumes = [{}];
  }
  nf.transporte.volumes[0].codigoRastreamento = trackCode;

  // 3. PUT com payload completo
  const url = `${CONFIG.bling.baseUrl}/nfe/${nfeId}`;
  try {
    const response = await axios.put(url, nf, {
      headers: {
        Authorization: `Bearer ${CONFIG.bling.accessToken}`,
        "Content-Type": "application/json",
      },
      timeout: 10000,
    });
    return response.status === 200 || response.status === 204;
  } catch (err) {
    const status = err.response?.status;
    if (status === 401) log("ERRO", "Token Bling expirado — renovar BLING_ACCESS_TOKEN");
    log("ERRO", `Bling PUT error ${status}`, { nfeId, trackCode, data: err.response?.data });
    return false;
  }
}

// ============================================================
// PROCESSAMENTO PRINCIPAL
// ============================================================
async function processarNF(nfeId, chaveNF) {
  log("INFO", `Iniciando NF`, { nfeId, chaveNF });

  let trackCode = null;

  for (let i = 1; i <= CONFIG.retry.tentativas; i++) {
    log("INFO", `Tentativa ${i}/${CONFIG.retry.tentativas}`);
    trackCode = await buscarTrackingFreteBararato(chaveNF);
    if (trackCode) { log("INFO", `Tracking: ${trackCode}`); break; }
    if (i < CONFIG.retry.tentativas) {
      log("INFO", `Aguardando ${CONFIG.retry.intervaloMs / 1000}s...`);
      await sleep(CONFIG.retry.intervaloMs);
    }
  }

  if (!trackCode) {
    log("AVISO", `Sem tracking após ${CONFIG.retry.tentativas} tentativas — fila`, { nfeId, chaveNF });
    fila.set(chaveNF, { nfeId, tentativas: 0, timestamp: Date.now() });
    return false;
  }

  const sucesso = await gravarTrackingBling(nfeId, trackCode);
  if (sucesso) {
    log("OK", `Tracking gravado no Bling`, { nfeId, trackCode });
    fila.delete(chaveNF);
    return true;
  }

  log("ERRO", `Falha Bling — fila`, { nfeId, trackCode });
  fila.set(chaveNF, { nfeId, tentativas: 0, timestamp: Date.now() });
  return false;
}

// ============================================================
// WEBHOOK DO BLING
// ============================================================
app.post("/webhook/bling", (req, res) => {
  if (!verificarAssinaturaBling(req)) {
    return res.status(401).json({ error: "assinatura inválida" });
  }

  const body = req.body;
  log("INFO", `Webhook`, { event: body?.event, nfeId: body?.data?.id });

  if (!body || body.event !== "nfe.authorized") {
    return res.status(200).json({ ok: true, msg: "evento ignorado" });
  }

  const nfeId = body.data?.id;
  const chaveNF = body.data?.chave;

  if (!nfeId || !chaveNF) {
    return res.status(400).json({ error: "dados incompletos" });
  }

  if (!/^\d{44}$/.test(chaveNF)) {
    return res.status(400).json({ error: "chave NF inválida" });
  }

  // Responde imediatamente ao Bling (evita timeout)
  res.status(200).json({ ok: true, msg: "processando" });

  processarNF(nfeId, chaveNF).catch((err) => {
    log("ERRO", "Erro inesperado", { error: err.message });
  });
});

// ============================================================
// JOB: Reprocessar fila a cada 10 minutos
// Flag isRunning evita overlap se uma rodada demorar >10min
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
      const trackCode = await buscarTrackingFreteBararato(chaveNF);
      if (trackCode) {
        const ok = await gravarTrackingBling(item.nfeId, trackCode);
        if (ok) { log("OK", `Reprocessada: ${chaveNF}`); fila.delete(chaveNF); }
      }
      // Desistir após 24h
      if (Date.now() - item.timestamp > 24 * 60 * 60 * 1000) {
        log("AVISO", `Descartada após 24h: ${chaveNF}`);
        fila.delete(chaveNF);
      }
    }
  } catch (err) {
    log("ERRO", "Erro inesperado no job de reprocessamento", { error: err.message });
  } finally {
    jobRunning = false; // SEMPRE libera o lock, mesmo em caso de erro
  }
}, 10 * 60 * 1000);

// ============================================================
// HEALTH CHECK
// ============================================================
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    fila: fila.size,
    filaNFs: Array.from(fila.keys()),
    uptime: Math.floor(process.uptime()) + "s",
    timestamp: new Date().toISOString(),
  });
});

// ============================================================
// REPROCESSAMENTO MANUAL (protegido por x-api-key)
// ============================================================
app.post("/reprocessar", autenticarApiKey, async (req, res) => {
  const { nfeId, chaveNF } = req.body || {};
  if (!nfeId || !chaveNF) {
    return res.status(400).json({ error: "nfeId e chaveNF obrigatórios" });
  }
  if (!/^\d{44}$/.test(chaveNF)) {
    return res.status(400).json({ error: "chaveNF inválida" });
  }
  res.json({ ok: true, msg: "processando" });
  processarNF(nfeId, chaveNF)
    .then((ok) => log("INFO", `Reprocessamento manual: ${ok ? "OK" : "FALHOU"}`))
    .catch((err) => log("ERRO", "Reprocessamento manual erro", { error: err.message }));
});

// ============================================================
// INICIAR — validar env vars obrigatórias antes de subir
// ============================================================
const VARS_OBRIGATORIAS = [
  "BLING_ACCESS_TOKEN",
  "FRETEBARATO_TOKEN",
  "FRETEBARATO_CUSTOMER_ID",
  "EMPRESA_CNPJ",
];
const varsFaltando = VARS_OBRIGATORIAS.filter(v => !process.env[v]);
if (varsFaltando.length > 0) {
  console.error(`[ERRO FATAL] Variáveis não configuradas: ${varsFaltando.join(", ")}`);
  console.error("Configure o arquivo .env e reinicie.");
  process.exit(1);
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  log("INFO", `Servidor na porta ${PORT}`);
  if (!CONFIG.bling.webhookSecret) log("AVISO", "Configure BLING_WEBHOOK_SECRET!");
  if (!CONFIG.servidor.apiKey)     log("AVISO", "Configure WEBHOOK_API_KEY!");
});

module.exports = { app, fila };
