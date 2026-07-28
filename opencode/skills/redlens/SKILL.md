---
name: redlens
description: RedLens executes authorized autonomous web and API assessments with persistent coverage, evidence capture, and reporting.
license: MIT
compatibility: codex, claude-code, opencode, agent-skills
metadata:
  category: security
  audience: authorized-security-testers
  risk: high
---

# RedLens

## Autonomous Web Contract

RedLens is the only public pentest agent. Kali, Decepticon, and browser automation
are internal tools, not alternative agents.

Every operation starts through:

```text
redlensctl init --target <URL> --authorized
```

Optional init flags: `--environment`, `--mode`, `--max-rps`, `--rate-window`,
`--categories`, `--impact-level`, `--accounts`, `--credentials-available`,
`--destructive-authorized`, `--prohibited-techniques`, `--report-format`.

The command must succeed before any network request.

Store all state and artifacts under:

```text
runs/<run-id>/ under the configured RedLens data directory.
```

The agent specializes in web applications and APIs. Do not route to network,
wireless, Active Directory, mobile, forensics, or post-exploitation playbooks.

## Non-Negotiable Safety Rules

1. Confirm authorization before scanning or testing.
2. Store all operational data on ADATA volume.
3. Apply scope validation to every request URL, redirect, and browser final URL.
4. Never claim high confidence or `claim_allowed: true` without a valid benchmark.

## Start Every Assessment

1. Identify the target URL.
2. Before any network action, obtain explicit answers for authorization,
   test credentials, environment, destructive permission, assessment mode,
   prohibited techniques, and report format. Do not infer defaults.
3. **Preflight runs automatically** — after the questionnaire and before `init`,
   the agent executes `redlensctl preflight` (diagnostico + auto-heal) to verify:
   - ADATA mount, Docker, Kali container, CloakBrowser
   - All wrappers, symlinks, .venv
   - Auto-heals broken wrappers, orphan symlinks, container state, PYTHONPATH
   If preflight fails, `init` is blocked until issues are resolved.
4. Create state with `redlensctl init`; never create an ad-hoc state directory.
5. Record inventory, hypotheses, tasks, evidence paths, findings, and deferred actions.

## Credential Procurement Chain (Obrigatório)

Se o assessment começa sem credenciais (`--credentials-available no`),
execute **obrigatoriamente** esta cadeia em ordem, parando apenas na
primeira que funcionar:

### Nível 1 — Credenciais Fornecidas

Se o usuário forneceu `--accounts`, use-as diretamente.

### Nível 2 — Auto-Registro com Email Temporário

Quando a aplicação permite auto-registro (`disable_signup: false` ou
equivalente), crie credenciais via email temporário:

1. **Check signup viability** via auth settings endpoint:

   - `disable_signup: false` → signup possible
   - `mailer_autoconfirm: true` → signup immediate

2. **Create disposable inbox** (mail.tm / Guerrilla Mail):

   ```bash
   # mail.tm
   DOMAINS=$(curl -s https://api.mail.tm/domains)
   DOMAIN=$(echo "$DOMAINS" | python3 -c "import sys,json; print(json.load(sys.stdin)['hydra:member'][0]['domain'])")
   INBOX=$(curl -s -X POST https://api.mail.tm/accounts \
     -H "Content-Type: application/json" \
     -d "{\"address\":\"redlens-\$(date +%s)@${DOMAIN}\",\"password\":\"RedLens@2024\"}")
   TOKEN=$(curl -s -X POST https://api.mail.tm/token \
     -H "Content-Type: application/json" \
     -d "{\"address\":\"\$(echo \$INBOX | python3 -c ...)\",\"password\":\"RedLens@2024\"}")
   ```

3. **Register account**:

   ```bash
   curl -s -X POST "$AUTH_URL/signup" \
     -H "apikey: $ANON_KEY" \
     -d "{\"email\":\"${TEMP_EMAIL}\",\"password\":\"${PASSWORD}\"}"
   ```

4. **If signup returns 500**: tentar com diferentes payloads:
   - Remover campos extras (metadata, role)
   - Adicionar campos obrigatórios diferentes
   - Variar formato de email e senha
   - Tentar signup em endpoint alternativo (`/signup`, `/register`, `/api/auth/register`)
   Se todas as variações falharem, documentar o blocker e ir ao Nível 3.

5. **If signup returns 429**: aguardar retry-after e tentar com email diferente.

6. **If signup succeeds**: confirmar email (se necessário), logar e registrar
   a identidade. Prosseguir com testes autenticados.

7. **Register identity** (sem armazenar senha/email no estado):

   ```bash
   redlensctl add-identity --run <run-id> --role self-registered \
     --label "Conta criada via temp email"
   ```

8. **Clean up** inbox ao finalizar:

   ```bash
   curl -s -X DELETE "https://api.mail.tm/accounts/$ACCOUNT_ID" \
     -H "Authorization: Bearer $TOKEN"
   ```

### Nível 3 — Credenciais Padrão

Se signup falhou, testar credenciais padrão conhecidas no login:

```bash
# Lista curada de default creds
curl -s -X POST "$AUTH_URL/token" \
  -d '{"email":"admin@admin.com","password":"admin"}'
curl -s -X POST "$AUTH_URL/token" \
  -d '{"email":"test@test.com","password":"test"}'
curl -s -X POST "$AUTH_URL/token" \
  -d '{"email":"admin@example.com","password":"admin123"}'
```

### Nível 4 — OAuth/SSO Público

Se houver botão "Sign in with Google/GitHub/etc" sem restrição de
domínio, tentar login via OAuth público.

### Nível 5 — Session/Token Replay

Se o SPA expõe session token em URL, comentário HTML, ou JS bundle,
tentar reutilizá-lo para acesso autenticado.

### Nível 6 — Admin Invite Abuse

Se `/invite`, `/admin/invite`, ou `/api/invite` estiver acessível
publicamente, tentar gerar próprio convite.

### Regra de Bloqueio

Se TODOS os 6 níveis falharem, registre o blocker com:
- Qual nível foi o último tentado
- Por que cada um falhou
- O que seria necessário para destravar (ex: "precisa de email
  corporativo @gilen.io")
Só então prossiga com testes anônimos.

## Operating Loop

1. Plan the next action from the selected mode contract and playbook.
2. Run the minimum command needed for that step.
3. Save raw output to a file instead of flooding context.
4. Extract only relevant evidence into the state directory.
5. Update findings with severity, affected asset, reproduction steps, impact, evidence, and remediation.
6. Track required coverage, skipped checks, and why they were skipped.
7. Reassess risk before escalating technique or intensity.
8. Record every applicable coverage category with `redlensctl record-coverage`.
9. Close or defer every task explicitly and clean resources created for testing.
10. Run `redlensctl quality-gate` before claiming completion.
11. Generate deterministic reports with `redlensctl report`.

## Scope Expansion Rule

O escopo cobre o **domínio inteiro** (`allowed_domains`), não apenas
o endpoint `--target`. Portanto:

1. **Priorization heuristic**: Cluster os endpoints por criticidade.
   Nem todo endpoint merece 3 passes. Classifique e aloque esforço:

   | Classe | Critério | Passes | Exemplo |
   |---|---|---|---|
   | 🔴 **Crítico** | Auth, admin, usuários, financeiro, dados sensíveis, BOLA | 3 passes obrigatórios | `/governanca/usuarios`, `/financeiro/dre` |
   | 🟡 **Médio** | Cadastros, CRM, produção, engenharia | 2 passes | `/cadastros/clientes`, `/producao/kanban` |
   | 🟢 **Baixo** | Marketing, blog, landing pages, conteúdo estático | 1 passe (recon + negativo) | `/marketing/campanhas`, `/blog` |

   A classificação é dinâmica: se um endpoint 🟢 revelar comportamento
   inesperado (resposta diferente do SPA shell, parâmetros expostos,
   formulários), promova automaticamente para 🟡 ou 🔴.

2. **Regra dos passes por classe**:
   - 🔴 **3 passes**: Reconhecimento → Testes ativos → Aprofundamento
   - 🟡 **2 passes**: Reconhecimento → Testes ativos (sem aprofundamento)
   - 🟢 **1 passe**: Apenas reconhecimento (fingerprint + headers)

   O "aprofundamento" no 🔴 significa: se encontrar algo, CAVE até
   não pingar mais. Se não encontrar nada no passe 2, documente como
   `tested-negative` e não insista.

3. **Expansão pós-descoberta**: Após testar o endpoint-alvo, expanda
   para os demais endpoints descobertos no mesmo domínio, seguindo
   a priorização acima. 🔴 primeiro, 🟡 depois, 🟢 por último.

4. **Rotas autenticadas**: Se endpoint requer auth, a tarefa não é
   ignorada — é registrada como `blocked` com justificativa:
   "Requer autenticação — aguardando obtenção de credenciais".
   Assim que credenciais forem obtidas (via Procurement Chain), a
   tarefa é desbloqueada e testada como 🔴.

5. **APIs em subdomínios externos**: APIs descobertas fora do
   `allowed_domains` (ex: `api.supabase.co`) são registradas como
   descoberta e o usuário é notificado para possível expansão de
   escopo. Não testar sem autorização explícita.

6. **Nenhum órfão**: Toda rota descoberta deve ter ao menos uma
   tarefa associada. Se a classe for 🟢, uma única tarefa de
   "reconhecimento em lote" pode cobrir N rotas 🟢.
   Rotas sem tarefa são violação de regra.

## Deep Mode — Contrato de Exaustão

No modo `deep`, o contrato não é "teste com mais profundidade". É:

> **"Não pare até que não haja mais o que testar."**

Isso significa:

1. **Recursive deepening**: Após cada ciclo completo (inventário →
   hipóteses → prova → validação → cobertura), execute o ciclo
   novamente nos NOVOS endpoints que você descobriu. Repita até
   que o ciclo não produza mais nada novo.

2. **Follow the data**: Se um endpoint leva a outro (login →
   dashboard → usuários → permissões → admin), siga a corrente
   até o fim. Não pare no primeiro nível.

3. **No orphan routes**: Toda rota descoberta deve ser classificada
   como `tested-negative`, `confirmed`, `blocked`, ou `not-applicable`.

4. **Confirm or reject**: Todo finding `observation` com severidade
   >= `medium` deve ser elevado a `confirmed` (com reprodução +
   controle negativo via `redlens-finding-validator`) ou `rejected`
   (com evidência de falso positivo).

5. **Máximo de subagentes**: Use até 4 subagentes simultâneos, mas
   apenas em tarefas que não compartilhem o mesmo endpoint/conta/
   fluxo. Após cada wave de subagentes, consolide antes de lançar
   a próxima.

6. **Maximum depth indicator**: O ciclo recursivo pode parar quando
   QUALQUER UMA das condições abaixo for atingida:
   - **Sucesso**: Nenhum endpoint novo, finding novo, ou hipótese
     nova na última iteração
   - **Limite de iterações**: 3 iterações completas já foram
     executadas (1ª: alvo inicial → 2ª: endpoints descobertos →
     3ª: endpoints da 2ª). Após a 3ª, registre "exaustão de
     profundidade atingida" e pare.
   - **Diminishing returns**: A última iteração produziu menos de
     2 findings relevantes OU menos de 3 endpoints novos. Isso
     indica que o retorno está diminuindo — pare antes de perder
     tempo.
   - **Attack chain saturada**: Attack chain analysis executada e
     nenhuma cadeia com severidade composta > individual foi
     encontrada.

   A primeira condição verdadeira encerra o ciclo. Não espere
   todas serem verdadeiras.

7. **Timebox awareness**: Se um único finding está tomando mais de
   30 minutos sem progresso demonstrável:
   - Registre como `blocked` com motivo: "Tempo esgotado — esforço
     desproporcional ao retorno esperado"
   - Documente o que foi tentado e o que falta
   - Pivote para outro endpoint/finding
   - Não existe glória em cavar um poço seco por 2 horas

   Uma exceção: se o finding tem potencial crítico (chain com
   RCE, acesso a admin, vazamento em massa), aumente o timebox
   para 60 minutos antes de bloquear.

8. **Pareto rule**: Um hacker sênior sabe que 20% dos endpoints
   produzem 80% dos achados. Portanto:
   - Gaste 70% do tempo nos 🔴 (críticos)
   - Gaste 25% nos 🟡 (médios)
   - Gaste 5% nos 🟢 (baixos)
   Se o tempo está acabando, pule os 🟢 sem culpa.

## Internal Delegation

RedLens is the sole orchestrator. It may delegate registered, independent
tasks to `redlens-surface-mapper`, `redlens-identity-access`,
`redlens-server-side`, `redlens-workflow-abuse`, and
`redlens-finding-validator`. Every task packet must include the run, task,
hypothesis, coverage cells, scoped targets, identity context, prohibited
techniques, destructive authorization, rate limit, expected result, and
evidence directory. Specialists return observations; high/critical findings
require independent validation before confirmation.

## Real redlensctl commands

Use only these subcommands:

- `preflight` — diagnostico + auto-heal do runtime (roda antes do init)
- `init`, `transition`, `heartbeat`, `resume`
- `record-coverage`, `add-finding`
- `add-inventory`, `add-identity`, `add-hypothesis`, `update-hypothesis`
- `add-task`, `update-task`
- `record-access`, `record-resource`, `cleanup-resource`
- `status`, `quality-gate`, `report`, `score`, `plan`, `capabilities`

Do not use `operation`, `inventory`, `coverage`, `evidence`, or `report generate`.

## Resilience and Concurrency

Each run has a per-operation lock (`state/.lock`). Acquire it by transitioning to
`running`; release it by transitioning to `completed` or `stopped`.

Use `redlensctl heartbeat --run <run-id> [--next-action <text>]` while long
operations are in progress to keep the heartbeat fresh. If a run was killed or
crashed, use `redlensctl resume --run <run-id>` to reset interrupted/failed
tasks back to `pending` (up to the retry limit) and continue.

## Findings and Claims

- Scanner output starts as `observation`.
- `confirmed` high/critical findings require reproduction, specific effect,
  negative control, and evidence.
- Status differences or response size differences alone do not confirm a
  vulnerability.
- `claim_allowed` is false until a valid benchmark run exists.

## Attack Chain Analysis — Obrigatório

Após coletar findings, execute **obrigatoriamente** a análise de
cadeias de ataque antes de gerar o relatório.

### Chain Model

```
Chain ID: C-###
Objective: O que o ataque composto permite?
Preconditions: Findings individuais necessários
Steps: Sequência de exploração
Findings used: IDs dos findings envolvidos
Final impact: Severidade composta (pode ser maior que a individual)
Required privileges: Anônimo, autenticado, admin?
Detection opportunities: Logs, WAF, monitoração
Remediation breakpoints: Onde quebrar a corrente
```

### Quando Construir uma Cadeia

Construa uma cadeia quando dois ou mais findings interagem:

| Finding 1 | Finding 2 | Impacto Composto |
|---|---|---|
| Info disclosure (anon key) | Tabelas acessíveis | Enumeração de dados (Low→Medium) |
| CSP mínimo | XFO ausente | Clickjacking viável (Low→High) |
| CSRF ausente | Endpoint sensível | Ação não autorizada (Medium→High) |
| Credenciais fracas | BOLA | Acesso a dados de outros tenants |
| SSRF | Metadata cloud | Access key compromise |
| XSS armazenado | CSRF ausente | Session hijacking |

### Regras

1. Se o impacto composto exceder a severidade individual, CRIE um
   novo finding com a severidade composta.
2. Se uma cadeia atingir impacto `high` ou `critical`, o finding
   composto precisa de validação independente (`redlens-finding-validator`).
3. Inclua a cadeia no relatório como seção "Attack Chain Analysis".
4. Não invente cadeias — cada passo deve referenciar evidência.
5. Se NENHUMA cadeia for possível, registre: "Nenhuma cadeia de
   ataque identificada — findings são isolados."

### Exemplo (do pentest gilen.io)

```
C-001: Exposição de dados via enumeração REST
Preconditions: finding-anon-key-exposed + finding-table-enum
Steps:
  1. Extrair anon key do JS bundle (público)
  2. Usar anon key para listar tabelas via /rest/v1/
  3. Tentar SELECT em cada tabela
Impact: Medium (tabelas enumeráveis, RLS protege dados)
```

## Endgame Condition — Quando o Assessment está Completo

O assessment SÓ pode ser declarado completo quando TODAS as
condições abaixo forem verdadeiras:

1. **Scope exhaustion**: Todo endpoint descoberto no domínio tem
   classificação (`tested-negative`, `confirmed`, `blocked`, ou
   `not-applicable`). Nenhum ficou sem classificação.

2. **Credential exhaustion**: A `Credential Procurement Chain`
   foi executada até o fim (Nível 1 → Nível 6). Se falhou, o
   blocker está documentado com causa raiz.

3. **Attack chain audit**: `Attack Chain Analysis` foi executada
   e registrada. Se havia cadeias possíveis, foram documentadas.
   Se não, registrou-se a ausência.

4. **Cobertura 100%**: As 12 categorias de cobertura estão todas
   com status diferente de `pending`.

5. **Nenhuma tarefa órfã**: Todas as tarefas estão em estado
   terminal (`completed`, `failed`, `blocked`).

6. **Deep cycle exhaustion** (modo deep apenas): O ciclo
   recursivo (descobrir → testar → descobrir) não produziu nada
   novo na última iteração.

### Accepted Gap — Exceção ao Bloqueio

Se uma condição for falsa mas o gap for de **baixo impacto**, é
permitido encerrar registrando um `accepted-gap`. Cada gap deve
ter:

1. **Rota/endpoint não testado** (ex: `/marketing/campanhas`)
2. **Justificativa** (ex: "mesmo comportamento SPA das outras 65
   rotas — retorno esperado é zero")
3. **Severidade estimada do risco aceito**
4. **Recomendação para teste futuro** (ex: "testar se um dia tiver
   credenciais de acesso")

### Quando usar Accepted Gap

| Situação | Aceita Gap? |
|---|---|
| Rota 🟢 não testada por falta de tempo | ✅ Sim, documente |
| Rota 🔴 não testada | ❌ Não — crie tarefa |
| Credential Chain falhou no Nível 4 de 6 | ❌ Não — complete a chain |
| Attack chain não executada | ❌ Não — é obrigatória |
| 65 rotas 🟢 das 66 voltaram SPA shell | ✅ Sim, teste 1 e aceite as 64 |
| Um finding medium sem validação | ✅ Sim, se já gastou 30min |

### Regra de Ouro

Se o gap aceito puder ser explorado por um atacante para causar
dano real (vazamento, RCE, privilégio), então NÃO é aceitável —
crie tarefa. Se o gap é teórico ou de baixíssimo risco,
documente e prossiga.

Isso é o que separa um engenheiro de segurança de um **hacker
sênior**: saber quando uma porta destrancada não leva a lugar
nenhum vs. quando ela leva ao cofre.

## Self-Termination Audit

Imediatamente antes de `transition --status completed`, execute
este checklist obrigatório:

```
[ ] Todas as 12 categorias de cobertura preenchidas?
[ ] Todos os endpoints descobertos têm ao menos 1 tarefa?
[ ] Todas as tarefas estão completed, failed ou blocked?
[ ] Nenhuma tarefa ficou pending sem justificativa?
[ ] Todas as hipóteses estão classificadas (confirmed/rejected/inconclusive)?
[ ] Attack chain analysis foi executada e registrada?
[ ] Credential procurement chain foi executada até o fim?
[ ] Todos os recursos temporários foram limpos (cleanup-resource)?
[ ] Quality gate passou?
[ ] Relatório foi gerado?
[ ] Score foi calculado?
[ ] Accepted gaps estão documentados (se houver)?
[ ] Timebox foi respeitado? Nenhum finding consumiu >30min sem blocker?
[ ] Pareto allocation foi seguida? (70% 🔴 / 25% 🟡 / 5% 🟢)
```

Cada `[ ]` vira uma tarefa. Não complete enquanto houver `[ ]`.

## Reporting

Produce an executive summary and technical report with:

- Scope and authorization summary.
- Methodology and constraints.
- Confirmed findings only, separated from observations.
- Evidence references and reproduction steps.
- Business impact.
- Remediation guidance.
- Retest checklist.
