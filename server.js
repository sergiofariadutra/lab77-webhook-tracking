/**
 * LAB77 / GRUPO 77
 * Webhook: Frete Barato → Bling
 * v3.0 — OAuth2 com refresh automático
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

// ============================================================
// CONFIGURAÇÕES
// ============================================================
const CONFIG = {
  bling: {
    clientId: process.env.BLING_CLIENT_ID,
    clientSecret: process.env.BLING_CLIENT_SECRET,
    baseUrl: "https://www.bling.com.br/Api/v3",
    oauthUrl: "https://www.bling.com.br/Api/v3/oauth/token",
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
    baseUrl: process.env.BASE_URL || "http://localhost:3000",
  },
  retry: {
    tentativas: 6,
    intervaloMs: 30000,
  },
};

// ============================================================
// GERENCIAMENTO DE TOKENS BLING (OAuth2)
// Persiste em arquivo para sobreviver a restarts
// ============================================================
const TOKEN_FILE = path.join(__dirname, ".bling-tokens.json");

let blingTokens = {
  accessToken: null,
  refreshToken: null,
  expiresAt: 0,
};

function salvarTokens() {
  try {
    fs.writeFileSync(TOKEN_FILE, JSON.stringify(blingTokens, null, 2));
    log("INFO", "Tokens salvos em disco");
  } catch (err) {
    log("ERRO", "Falha ao salvar tokens", { error: err.message });
  }
}

function carregarTokens() {
  try {
    if (fs.existsSync(TOKEN_FILE)) {
      const data = JSON.parse(fs.readFileSync(TOKEN_FILE, "utf-8"));
      blingTokens = data;
      log("INFO", "Tokens carregados do disco", {
        temAccessToken: !!data.accessToken,
        temRefreshToken: !!data.refreshToken,
        expiraEm: new Date(data.expiresAt).toISOString(),
      });
    }
  } catch (err) {
    log("AVISO", "Sem tokens salvos — aguardando OAuth via /callback");
  }
}

function basicAuthHeader() {
  return "Basic " + Buffer.from(
    `${CONFIG.bling.clientId}:${CONFIG.bling.clientSecret}`
  ).toString("base64");
}

async function trocarCodePorTokens(code) {
  const res = await axios.post(CONFIG.bling.oauthUrl, {
    grant_type: "authorization_code",
    code,
  }, {
    headers: {
      Authorization: basicAuthHeader(),
      "Content-Type": "application/json",
    },
    timeout: 15000,
  });

  const { access_token, refresh_token, expires_in } = res.data;
  blingTokens = {
    accessToken: access_token,
    refreshToken: refresh_token,
    expiresAt: Date.now() + (expires_in * 1000) - 60000, // renova 1min antes
  };
  salvarTokens();
  log("OK", "Tokens obtidos via authorization_code", { expires_in });
}

async function refreshBlingToken() {
  if (!blingTokens.refreshToken) {
    throw new Error("Sem refresh_token — faça o OAuth via /callback primeiro");
  }

  log("INFO", "Renovando access_token via refresh_token...");
  const res = await axios.post(CONFIG.bling.oauthUrl, {
    grant_type: "refresh_token",
    refresh_token: blingTokens.refreshToken,
  }, {
    headers: {
      Authorization: basicAuthHeader(),
      "Content-Type": "application/json",
    },
    timeout: 15000,
  });

  const { access_token, refresh_token, expires_in } = res.data;
  blingTokens = {
    accessToken: access_token,
    refreshToken: refresh_token,
    expiresAt: Date.now() + (expires_in * 1000) - 60000,
  };
  salvarTokens();
  log("OK", "Token renovado com sucesso", { expires_in });
}

async function getBlingAccessToken() {
  if (blingTokens.accessToken && Date.now() < blingTokens.expiresAt) {
    return blingTokens.accessToken;
  }
  await refreshBlingToken();
  return blingTokens.accessToken;
}

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
// BLING OAuth2 — Rota /callback
// ============================================================
app.get("/callback", async (req, res) => {
  const { code, state } = req.query;

  if (!code) {
    return res.status(400).json({ error: "Parâmetro 'code' ausente" });
  }

  try {
    await trocarCodePorTokens(code);
    res.json({
      ok: true,
      msg: "OAuth concluído! Tokens salvos. O webhook está pronto.",
      expiraEm: new Date(blingTokens.expiresAt).toISOString(),
    });
  } catch (err) {
    log("ERRO", "Falha no OAuth callback", { error: err.message, data: err.response?.data });
    res.status(500).json({
      error: "Falha ao obter tokens",
      detalhes: err.response?.data || err.message,
    });
  }
});

// Rota auxiliar: gera a URL de autorização para facilitar o setup
app.get("/authorize", (req, res) => {
  const authUrl = `https://www.bling.com.br/Api/v3/oauth/authorize`
    + `?response_type=code`
    + `&client_id=${CONFIG.bling.clientId}`
    + `&state=lab77`;
  res.json({
    msg: "Acesse a URL abaixo no navegador para autorizar o app:",
    url: authUrl,
  });
});

// ============================================================
// BLING — Gravar tracking na NF (com refresh automático)
// ============================================================
async function gravarTrackingBling(nfeId, trackCode) {
  const url = `${CONFIG.bling.baseUrl}/nfe/${nfeId}/rastreamentos`;

  try {
    const accessToken = await getBlingAccessToken();
    const response = await axios.put(
      url,
      { rastreamentos: [{ codigo: trackCode }] },
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json",
        },
        timeout: 10000,
      }
    );
    return response.status === 200 || response.status === 204;

  } catch (err) {
    const status = err.response?.status;
    if (status === 401) {
      log("AVISO", "Token expirado, tentando refresh...");
      try {
        await refreshBlingToken();
        const novoToken = blingTokens.accessToken;
        const retry = await axios.put(
          url,
          { rastreamentos: [{ codigo: trackCode }] },
          {
            headers: {
              Authorization: `Bearer ${novoToken}`,
              "Content-Type": "application/json",
            },
            timeout: 10000,
          }
        );
        return retry.status === 200 || retry.status === 204;
      } catch (refreshErr) {
        log("ERRO", "Refresh falhou — faça OAuth novamente via /authorize", {
          error: refreshErr.message,
        });
        return false;
      }
    }
    log("ERRO", `Bling error ${status}`, { nfeId, trackCode, data: err.response?.data });
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
    blingToken: blingTokens.accessToken ? "ativo" : "ausente",
    blingTokenExpira: blingTokens.expiresAt ? new Date(blingTokens.expiresAt).toISOString() : null,
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
  "BLING_CLIENT_ID",
  "BLING_CLIENT_SECRET",
  "FRETEBARATO_TOKEN",
  "FRETEBARATO_CUSTOMER_ID",
  "EMPRESA_CNPJ",
];
const varsFaltando = VARS_OBRIGATORIAS.filter(v => !process.env[v]);
if (varsFaltando.length > 0) {
  console.error(`[ERRO FATAL] Variáveis não configuradas: ${varsFaltando.join(", ")}`);
  console.error("Configure as variáveis de ambiente e reinicie.");
  process.exit(1);
}

// Carregar tokens salvos (se existirem) antes de iniciar
carregarTokens();

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  log("INFO", `Servidor na porta ${PORT}`);
  log("INFO", `OAuth callback: ${CONFIG.servidor.baseUrl}/callback`);
  if (!blingTokens.accessToken) {
    log("AVISO", `Sem token Bling — acesse ${CONFIG.servidor.baseUrl}/authorize para autorizar`);
  }
  if (!CONFIG.bling.webhookSecret) log("AVISO", "Configure BLING_WEBHOOK_SECRET!");
  if (!CONFIG.servidor.apiKey)     log("AVISO", "Configure WEBHOOK_API_KEY!");
});

module.exports = { app, fila };
