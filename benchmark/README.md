# RedLens Benchmark Lab

Laboratorio local de alvos intencionalmente vulneraveis para medir o desempenho do RedLens sem tocar em nenhum sistema real.

## Alvos incluidos

| Servico     | URL                    | Porta | Foco principal                              |
|-------------|------------------------|-------|---------------------------------------------|
| Juice Shop  | http://localhost:13000 | 13000 | Autenticacao, autorizacao, XSS, logica de negocio |
| VAmPI       | http://localhost:15000 | 15000 | API REST, BOLA, JWT, mass assignment         |

## Requisitos

- Docker 24+
- Docker Compose 2.20+

## Subir o laboratorio

```bash
cd /Volumes/ADATA SC735/CYBERSECURITY/redlens/benchmark
./reset-lab.sh
```

O script:

1. remove containers e volumes antigos;
2. baixa as imagens mais recentes;
3. sobe os dois servicos;
4. aguarda os healthchecks ficarem `healthy`.

## Parar o laboratorio

```bash
docker compose -f lab-compose.yml down
```

## Destruir tudo e comecar do zero

```bash
docker compose -f lab-compose.yml down -v
```

## Ground truth

O arquivo `ground-truth.json` lista as vulnerabilidades conhecidas que o RedLens deve tentar encontrar. Ele e usado para calcular:

- **recall**: quantas vulnerabilidades conhecidas foram confirmadas;
- **precisao**: quantos achados do RedLens correspondem a itens reais do ground truth.

## Usar no RedLens

Depois que o laboratorio estiver no ar, inicie uma operacao contra um dos alvos:

```bash
python3 redlens/engine/redlensctl.py init \
  --target http://localhost:13000 \
  --authorization-reference local-benchmark \
  --authorized \
  --environment staging
```

## Seguranca

- Todo o trafego fica na interface de loopback (`localhost`).
- Nenhuma informacao real e processada pelos alvos.
- Execute somente neste ambiente controlado.
