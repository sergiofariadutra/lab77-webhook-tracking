const { test } = require("node:test");
const assert = require("node:assert/strict");
const { isInsufficientScope, escapeHtml, envFlag } = require("../lib/helpers");

function erroAxios(status, data, headers = {}) {
  return { response: { status, data, headers } };
}

test("isInsufficientScope: 403 com insufficient_scope no body", () => {
  assert.equal(isInsufficientScope(erroAxios(403, { error: { type: "insufficient_scope", description: "..." } })), true);
});

test("isInsufficientScope: 403 com insufficient_scope no header WWW-Authenticate (RFC 6750)", () => {
  assert.equal(isInsufficientScope(erroAxios(403, {}, { "www-authenticate": 'Bearer error="insufficient_scope"' })), true);
});

test("isInsufficientScope: 403 genérico NÃO marca escopo", () => {
  assert.equal(isInsufficientScope(erroAxios(403, { error: "forbidden" })), false);
});

test("isInsufficientScope: 401 nunca marca, mesmo com texto parecido", () => {
  assert.equal(isInsufficientScope(erroAxios(401, { error: "insufficient_scope" })), false);
});

test("isInsufficientScope: erro sem response (timeout/rede)", () => {
  assert.equal(isInsufficientScope(new Error("ETIMEDOUT")), false);
  assert.equal(isInsufficientScope(null), false);
});

test("isInsufficientScope: body string e body circular não explodem", () => {
  assert.equal(isInsufficientScope(erroAxios(403, "insufficient_scope")), true);
  const circular = {}; circular.self = circular;
  assert.equal(isInsufficientScope(erroAxios(403, circular)), false);
});

test("escapeHtml: neutraliza payload de XSS", () => {
  assert.equal(escapeHtml('<script>alert(1)</script>'), "&lt;script&gt;alert(1)&lt;/script&gt;");
  assert.equal(escapeHtml('Loja "A" & B'), "Loja &quot;A&quot; &amp; B");
});

test("escapeHtml: null/undefined/número viram string segura", () => {
  assert.equal(escapeHtml(null), "");
  assert.equal(escapeHtml(undefined), "");
  assert.equal(escapeHtml(1423), "1423");
});

test("envFlag: liga com 1/true/sim em qualquer caixa, desliga no resto", () => {
  for (const v of ["1", "true", "TRUE", "sim", "Sim "]) assert.equal(envFlag(v), true, v);
  for (const v of ["", "0", "false", "não", undefined, null]) assert.equal(envFlag(v), false, String(v));
});
