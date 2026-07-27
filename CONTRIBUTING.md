# Contribuindo com o RedLens

## Ambiente

Use Python 3.12 e Docker. O bootstrap cria um virtualenv local, instala o
projeto em modo editavel e valida a configuracao:

```sh
REDLENS_PYTHON=python3.12 ./runtime/bootstrap.sh
```

Ative o ambiente antes de usar os comandos:

```sh
source .venv/bin/activate
redlens doctor
```

## Checks locais

```sh
python -m compileall -q redlens_config.py redlens_entrypoints.py engine adapters runtime
python -m unittest discover -s tests -p 'test_*.py'
docker compose -f runtime/compose.yaml config --quiet
```

Nao execute testes contra alvos reais. Use fixtures e o laboratorio local.
Operacoes reais continuam exigindo autorizacao explicita pelo fluxo RedLens.

## Regras de mudanca

- Nao adicionar paths, usuarios ou volumes locais ao codigo.
- Nao versionar evidencias, relatorios, caches de navegador ou configuracao local.
- Manter dados operacionais no diretorio configurado; veja `DATA_BOUNDARY.md`.
- Nao chamar Docker diretamente de um adapter; use o Runtime Executor.
- Nao adicionar dependencia quando a biblioteca padrao resolver o problema.
- Toda mudanca de schema precisa de migracao e teste de upgrade.
- Toda alteracao no runtime deve manter `redlens doctor` e `redlens-health`
  verificaveis.

Para alterar o container operacional, use primeiro `redlens runtime preflight`.
Adocoes devem usar `redlens runtime adopt --image <tag-imutavel>`; nao remova o
container legado manualmente, pois o fluxo preserva rollback.
