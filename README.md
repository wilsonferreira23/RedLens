# RedLens

Agente único de pentest web do OpenCode.

## Uso

```text
/pentest https://alvo-autorizado.example
```

O agente exige autorização e escopo antes de qualquer requisição. Todo estado
é persistido em `runs/` no diretório de dados configurado.

## Bootstrap

Requisitos: Python 3.12+ e Docker Desktop ou Docker Engine.

```sh
./runtime/bootstrap.sh
```

Para construir e iniciar o runtime Kali durante o bootstrap:

```sh
REDLENS_BUILD_RUNTIME=1 ./runtime/bootstrap.sh
```

O local pode ser alterado sem editar código:

```sh
REDLENS_HOME="$PWD" \
REDLENS_DATA_DIR="/path/to/redlens-data" \
./runtime/bootstrap.sh
```

Depois da instalação, use `redlens doctor`, `redlens health` e
`redlens runtime status`.

Para migrar o container manual atual para Compose com rollback disponível:

```sh
redlens runtime preflight
redlens runtime adopt --image redlens-kali:repro
redlens runtime rollback
```

`preflight` é somente leitura. `adopt` preserva o container antigo com nome
versionado, valida o health check e desfaz a troca se a validação falhar.

Para revisar ou migrar uma operação antiga com backup automático:

```sh
redlens migrate --run <run-id> --dry-run
redlens migrate --run <run-id>
```

O manifesto de ferramentas pode ser gerado sem dependências externas:

```sh
python -m runtime.manifest --output /tmp/redlens-sbom.json
```

Se o virtualenv nao estiver ativo, use os mesmos comandos com o prefixo
`$REDLENS_HOME/.venv/bin/` ou ative-o com `source .venv/bin/activate`.

## Diretórios

- `opencode/`: agente, comando e skill.
- `engine/`: autorização, escopo, cobertura e quality gate.
- `adapters/`: integrações internas.
- `runtime/`: workspace do Kali e referências ao Decepticon.
- `runs/`: operações e evidências, no diretório de dados configurado.
- `backups/`: backups operacionais, no diretório de dados configurado.
- `tests/`: verificações locais sem acesso a alvos.

Veja [DATA_BOUNDARY.md](DATA_BOUNDARY.md) antes de compartilhar o checkout.

O adapter de navegador mantém o CloakBrowser como backend principal. Chromium
Playwright existe apenas como contingência se o backend principal falhar. O
diagnóstico `redlens-health` verifica o runtime configurado, e CAPTCHA ou
desafios exigem intervenção humana.
