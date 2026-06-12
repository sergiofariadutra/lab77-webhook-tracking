# Migração Railway → VPS (72.60.154.208)

Runbook do cutover do lab77-webhook-tracking. Baseado na issue #1, refinado
durante os PRs 1/2. **Executar junto com o Sergio, fora do horário comercial
(seg–sex 8h–17h BRT).**

## A regra que governa tudo

O **refresh token do Bling rotaciona a cada uso**. Dois processos usando o
mesmo grant se matam mutuamente. Corolários:

1. Railway e VPS **nunca** podem estar os dois com token ativo.
2. **Setar/alterar qualquer variável no Railway dispara redeploy** — que mata
   os tokens de memória (e, antes do PR 1, qualquer token). Por isso o
   `/export-tokens` é **fallback**, não o caminho primário: o plano original
   ("seta `EXPORT_TOKENS_KEY` e exporta") se auto-sabota.
3. O caminho primário é **OAuth fresco na VPS** (`/authorize`), com o Railway
   já parado. Não há corrida: um grant novo nasce na VPS e o velho morre com o
   Railway.

## Estado de partida (conferir, não assumir)

| Item | Como conferir |
|---|---|
| Código na VPS em `/root/lab77-webhook-tracking` atualizado | `git -C /root/lab77-webhook-tracking pull` (precisa estar na main já com PRs 1+2) |
| `.env` da VPS preenchido, `chmod 600` | `ls -la /root/lab77-webhook-tracking/.env` — conferir contra `.env.example`. O `BLING_REFRESH_TOKEN` antigo está **inválido** (rotacionou) — pode apagar a linha |
| `EXPORT_TOKENS_KEY` **não** está no `.env` da VPS | `grep EXPORT_TOKENS /root/lab77-webhook-tracking/.env` → vazio |
| Rede `f77-net` existe e o f77-backend está nela | `docker network ls`; `docker network inspect f77-net` deve listar o container do f77-backend. Se a rede não existir: `docker network create f77-net` e conectar o backend (`docker network connect f77-net f77-backend`) |
| Webhook do Bling hoje aponta pro Railway | painel Bling → Webhooks (invoice.created/updated) |

## Pré-requisitos (Sergio, antes do dia D)

- [ ] PRs 1 e 2 mergeados na main (⚠️ o merge redeploya o Railway → fazer **uma**
      reautorização no `/authorize` do Railway pra ele seguir vivo até o cutover;
      conferir no log: `Tokens salvos em disco`)
- [ ] DNS: `tracking.fabrica77.com.br` → A `72.60.154.208`
- [ ] Painel `developer.bling.com.br`: **adicionar**
      `https://tracking.fabrica77.com.br/oauth/callback` como redirect URI.
      (Se o painel só aceita 1 URI, este passo migra pro dia D — a partir da
      troca, o `/authorize` do Railway quebra.)
- [ ] nginx + certbot na VPS com `deploy/nginx-tracking.conf` (junto com Sergio):
      `nginx -t && systemctl reload nginx`, depois
      `certbot --nginx -d tracking.fabrica77.com.br`

## Dia D

```text
1. VPS: preencher BASE_URL=https://tracking.fabrica77.com.br no .env
2. VPS: docker compose up -d --build
   → sobe SEM token (inofensivo: loga "SEM TOKEN", não rotaciona nada)
   → conferir: curl -s 127.0.0.1:3010/health  → status ok, blingToken ausente
   → conferir: ss -tlnp | grep 3010           → SÓ 127.0.0.1 (não 0.0.0.0)
3. Railway: anotar a fila pendente (se houver):
   curl -s -H "x-api-key: $KEY" https://<railway>/fila
4. Railway: PARAR o serviço (scale 0 / remover deploy). A partir daqui o
   grant antigo não rotaciona mais.
5. Bling: garantir redirect URI = https://tracking.fabrica77.com.br/oauth/callback
6. Navegador: https://tracking.fabrica77.com.br/authorize → autorizar
   → log: "OAUTH CONCLUÍDO" + "Tokens salvos em disco"
   → curl -s 127.0.0.1:3010/health → blingToken: ativo
7. Bling: apontar webhooks invoice.created/updated pra
   https://tracking.fabrica77.com.br/webhook/bling
   (secret = BLING_WEBHOOK_SECRET do .env da VPS — são novos, ≠ Railway)
8. f77-backend (.env na VPS): LAB77_RAILWAY_URL=http://lab77-webhook:8080
   + FEATURE_CRON_ETIQUETA_ECOMM=on  (liga a rede de segurança do cutover —
     ver "NFs da janela do cutover" abaixo; nasce desligada por padrão)
   → docker compose up -d f77-backend (sem build)
   → (nome da env LAB77_RAILWAY_URL mantido por compat; consumo agora é
     interno via f77-net)
```

### Validação fim-a-fim (ciclo completo, não só container vivo)

- [ ] `curl 127.0.0.1:3010/health` → `status: ok`, `blingToken: ativo`
- [ ] `https://tracking.fabrica77.com.br/painel` lista NFs
- [ ] `https://tracking.fabrica77.com.br/etiqueta/<id de NF real com envio>`
      retorna o PDF
- [ ] De dentro do backend: `docker exec f77-backend wget -qO- http://lab77-webhook:8080/health`
- [ ] Emitir/atualizar uma NF → webhook aparece no log
      (`docker logs -f lab77-webhook`)
- [ ] ERP → Expedição → Embalar um pedido real → etiqueta vem
- [ ] `docker restart lab77-webhook` → token **sobrevive**
      (log: `Tokens carregados do disco`; `/health` ativo sem reautorizar)

### NFs da janela do cutover

Entre o passo 4 (Railway parado) e o 7 (webhook reapontado), NFs autorizadas
não geram evento em lugar nenhum. Os pedidos e-commerce (f77/lab77) são curados
pelo cron do PR 3 (f77-backend), **desde que `FEATURE_CRON_ETIQUETA_ECOMM=on`
esteja no `.env` do f77-backend** (passo 8): ele completa chave + etiqueta
sozinho em ≤30min. Sem essa env o cron fica inerte e os pedidos ficam presos —
por isso ela faz parte do passo 8, não é opcional pro cutover.

Reprocessamento manual via `/reprocessar` **só faz sentido com
`GRAVAR_RASTREIO_BLING=1`** (gravação de rastreio no Bling). Como a gravação
está desligada por padrão, `/reprocessar` hoje só re-tenta o cache de etiqueta —
quem cura o lado ERP é o cron do PR 3, não o `/reprocessar`. Use o `/reprocessar`
apenas se a gravação de rastreio estiver religada e a fila (passo 3) não vazia:
`curl -X POST -H "x-api-key: ..." -d '{"nfeId":...,"chaveNF":"..."}' 127.0.0.1:3010/reprocessar`

### Rollback (se o passo 6/validação falhar)

O Railway parado **não foi deletado** — religar o serviço, reautorizar
`/authorize` no Railway (redirect URI de volta, se foi trocado no passo 5),
webhooks de volta pra URL Railway e `LAB77_RAILWAY_URL` de volta pra URL
pública do Railway. Nada na VPS precisa ser desfeito (container pode ficar
parado: `docker compose stop`).

## Pós-cutover (só depois da validação 100%)

- [ ] Deletar o serviço no Railway (projeto `kind-grace`)
- [ ] Remover `EXPORT_TOKENS_KEY` das variáveis (se o serviço for deletado,
      morre junto)
- [ ] Limpar `etiqueta_url` antiga: linhas de `pedido_ecommerce` com URL do
      Railway viram link morto (o `etiqueta_base64` continua funcionando):
      `UPDATE pedido_ecommerce SET etiqueta_url = REPLACE(etiqueta_url, 'https://<railway>', 'https://tracking.fabrica77.com.br') WHERE etiqueta_url LIKE '%railway%';`
- [ ] Monitorar 30min: `docker logs -f lab77-webhook` + fluxo completo de um
      pedido real

## Fallback: export de tokens (só se o OAuth fresco for inviável)

1. `EXPORT_TOKENS_KEY` **já** setada no Railway de antes? Se não, setar **vai
   redeployar** e exigir reautorização — fazer isso com antecedência, nunca no
   meio do cutover.
2. Parar TODO tráfego que cause refresh (webhook/painel/job) — na prática:
   só usar logo após um redeploy+reautorização, antes do token expirar (6h).
3. `GET https://<railway>/export-tokens?key=...` → copiar o JSON pra
   `/data/.bling-tokens.json` no volume da VPS (via `docker compose run` ou
   `docker cp`), `chmod 600`.
4. Parar o Railway ANTES de subir a VPS.
5. ⚠️ `EXPORT_TOKENS_KEY` **nunca** entra no `.env` da VPS.
