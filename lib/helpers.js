// Helpers puros extraídos do server.js pra serem testáveis (node --test).

// 403 de escopo OAuth insuficiente (RFC 6750: WWW-Authenticate traz
// error="insufficient_scope"; o Bling também costuma trazer no body).
function isInsufficientScope(err) {
  if (err?.response?.status !== 403) return false;
  const www = String(err.response.headers?.["www-authenticate"] || "");
  let body = "";
  try { body = JSON.stringify(err.response.data || ""); } catch { body = String(err.response.data); }
  return /insufficient_scope/i.test(www) || /insufficient_scope/i.test(body);
}

// Escape pra interpolação em HTML (nomes de cliente vêm do checkout — input externo)
function escapeHtml(valor) {
  return String(valor ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// Flag boolean de env: "1"/"true"/"sim" (case-insensitive) = ligado
function envFlag(valor) {
  return /^(1|true|sim)$/i.test(String(valor || "").trim());
}

module.exports = { isInsufficientScope, escapeHtml, envFlag };
