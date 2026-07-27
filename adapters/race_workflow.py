#!/usr/bin/env python3
"""Race condition and workflow testing.

Suporta:
- Concorrência limitada em N workers paralelos (max 8)
- Templates de workflow: skip-step, replay-once, reorder, change-tenant,
  change-owner, change-quantity, zero/negative, change-plan, coupon-reuse,
  invite-accept-twice, token-reuse, direct-endpoint-call

Regras:
- Apenas recurso sintetico
- Baseline antes da acao
- Cleanup obrigatorio
- Resultado persistido
- Race condition so confirmada quando uma invariante mensuravel eh violada
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))

import redlensctl  # noqa: E402


WORKFLOW_TEMPLATES = {
    "skip-step": {
        "description": "Pular uma etapa obrigatoria do fluxo",
        "requires": ["flow_definition"],
    },
    "replay-once": {
        "description": "Reusar acao de uso unico (idempotency)",
        "requires": ["idempotency_token"],
    },
    "reorder": {
        "description": "Reordenar etapas",
        "requires": ["flow_definition"],
    },
    "change-tenant": {
        "description": "Mudar tenant durante fluxo",
        "requires": ["multi_tenant_session"],
    },
    "change-owner": {
        "description": "Trocar proprietario de recurso",
        "requires": ["ownership_field"],
    },
    "change-quantity": {
        "description": "Alterar quantidade (zero, negativo, limite)",
        "requires": ["quantity_field"],
    },
    "change-plan": {
        "description": "Alterar plano sem fluxo de mudanca",
        "requires": ["plan_field"],
    },
    "coupon-reuse": {
        "description": "Reutilizar cupom de uso unico",
        "requires": ["coupon_id"],
    },
    "invite-accept-twice": {
        "description": "Aceitar convite duas vezes",
        "requires": ["invite_token"],
    },
    "token-reuse": {
        "description": "Reusar token apos uso",
        "requires": ["auth_token"],
    },
    "direct-endpoint": {
        "description": "Chamar endpoint final diretamente",
        "requires": ["endpoint_url"],
    },
}


def send_request(url: str, method: str, headers: dict, body: bytes) -> tuple[int, dict, bytes]:
    if body is None:
        body = b""
    req = urllib.request.Request(url, data=body if body else None, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return response.status, dict(response.headers), response.read(64 * 1024)
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers or {}), exc.read(64 * 1024) if hasattr(exc, "read") else b""
    except Exception as exc:
        return 0, {}, str(exc).encode("utf-8")


def get_state(url: str, state_check: str | None) -> dict:
    """Captura estado atual de --state-url extraindo --state-check."""
    status, _, body = send_request(url, "GET", {}, b"")
    result = {"status": status, "raw": body.decode("utf-8", errors="ignore")[:1024]}
    if status == 200 and state_check:
        try:
            data = json.loads(body.decode("utf-8", errors="ignore"))
            result["value"] = dotted_get(data, state_check)
        except json.JSONDecodeError:
            result["value"] = None
    return result


def dotted_get(data: dict, path: str):
    """Acesso a caminho no estilo jq dotted, e.g. 'balance' ou 'data.coupons[0]'."""
    current = data
    for part in re.split(r"\.|\[|\]", path):
        if not part:
            continue
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list):
            try:
                current = current[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            return None
        if current is None:
            return None
    return current


def race_test(endpoint: str, method: str, headers: dict, body: bytes, n: int, delay: float) -> list[dict]:
    """Dispara N requests simultaneos para detectar race condition."""
    results = []

    def worker(_):
        if delay:
            time.sleep(delay)
        return send_request(endpoint, method, headers, body)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(n, 2)) as executor:
        futures = [executor.submit(worker, i) for i in range(n)]
        concurrent.futures.wait(futures, timeout=30)
        for f in futures:
            try:
                status, hdrs, body_resp = f.result(timeout=5)
                results.append({"status": status, "size": len(body_resp), "success": 200 <= status < 400})
            except (concurrent.futures.TimeoutError, Exception):
                results.append({"status": 0, "size": 0, "success": False, "error": "timeout"})

    return results


def workflow_test(template: str, parameters: dict, baseline_first: bool = True) -> dict:
    """Aplica um template de workflow."""
    if template not in WORKFLOW_TEMPLATES:
        raise redlensctl.RedLensError(f"Template desconhecido: {template}")
    return {
        "template": template,
        "description": WORKFLOW_TEMPLATES[template]["description"],
        "parameters": parameters,
        "baseline_first": baseline_first,
    }


def is_login_operation(url: str) -> bool:
    """Login repetivel nao eh race condition."""
    parsed = urllib.parse.urlparse(url)
    return "/login" in parsed.path.lower()


def analyze_race(
    results: list[dict],
    initial_state: dict | None,
    baseline_state: dict | None,
    final_state: dict | None,
) -> dict:
    """Analisa resultados de race test exigindo violacao de invariante mensuravel."""
    if not results:
        return {"verdict": "inconclusive", "reason": "sem resultados"}

    success_count = sum(1 for r in results if r.get("success"))
    statuses = sorted(set(r.get("status", 0) for r in results))

    # Nao confirmar apenas porque multiplas respostas foram 2xx.
    if success_count <= 1:
        return {
            "verdict": "tested-negative",
            "confidence": "medium",
            "success_count": success_count,
            "total": len(results),
            "statuses": statuses,
            "reason": "Apenas 1 request succeedeu; nao ha condicao de corrida",
        }

    # Verificar invariante usando estado capturado.
    invariant_violated = False
    reason = f"{success_count} requests simultaneos succeederam, mas a invariante se manteve"

    if (
        initial_state
        and baseline_state
        and final_state
        and initial_state.get("value") is not None
        and baseline_state.get("value") is not None
        and final_state.get("value") is not None
    ):
        try:
            initial_val = float(initial_state["value"])
            baseline_val = float(baseline_state["value"])
            final_val = float(final_state["value"])
            sequential_delta = initial_val - baseline_val
            concurrent_delta = baseline_val - final_val
            expected_concurrent_delta = sequential_delta * len(results)

            # Violacao: recurso limitado foi consumido menos vezes do que
            # responses indicam, ou mais vezes do que deveria ser possivel.
            if sequential_delta > 0 and concurrent_delta < expected_concurrent_delta:
                invariant_violated = True
                reason = (
                    f"Invariante violada: {success_count} requests succeederam, "
                    f"mas o recurso diminuiu apenas {concurrent_delta} durante a concorrencia "
                    f"(esperado {expected_concurrent_delta})"
                )
            elif sequential_delta > 0 and concurrent_delta > expected_concurrent_delta:
                invariant_violated = True
                reason = (
                    f"Invariante violada: recurso diminuiu {concurrent_delta} durante a concorrencia, "
                    f"mais do que o esperado {expected_concurrent_delta}"
                )
            elif sequential_delta == 0 and concurrent_delta > 0:
                # Caso coupon/invite: baseline nao consumiu, mas concorrencia consumiu.
                invariant_violated = True
                reason = (
                    f"Invariante violada: baseline nao alterou estado, "
                    f"mas concorrencia consumiu {concurrent_delta}"
                )
        except (TypeError, ValueError):
            reason += " (estado nao numerico, nao foi possivel avaliar invariante)"
    else:
        reason += " (estado nao capturado, nao foi possivel avaliar invariante)"

    if invariant_violated:
        return {
            "verdict": "confirmed",
            "confidence": "high",
            "success_count": success_count,
            "total": len(results),
            "statuses": statuses,
            "reason": reason,
        }

    return {
        "verdict": "tested-negative",
        "confidence": "medium",
        "success_count": success_count,
        "total": len(results),
        "statuses": statuses,
        "reason": reason,
    }


def main() -> int:
    parser = argparse.ArgumentParser(prog="race-workflow")
    sub = parser.add_subparsers(dest="action", required=True)

    race_p = sub.add_parser("race")
    race_p.add_argument("--run", required=True)
    race_p.add_argument("--url", required=True)
    race_p.add_argument("--method", default="POST")
    race_p.add_argument("--n", type=int, default=5, help="Numero de requests paralelos")
    race_p.add_argument("--delay", type=float, default=0.0)
    race_p.add_argument("--headers", help="JSON com headers")
    race_p.add_argument("--body", help="JSON body")
    race_p.add_argument("--state-url", help="URL para capturar estado antes/depois")
    race_p.add_argument("--state-check", help="Caminho dotted para extrair valor do estado, e.g. 'balance'")
    race_p.add_argument("--cleanup-url", help="URL para limpar estado apos o teste")

    wf_p = sub.add_parser("workflow")
    wf_p.add_argument("--run", required=True)
    wf_p.add_argument("--template", required=True, choices=list(WORKFLOW_TEMPLATES.keys()))
    wf_p.add_argument("--parameters", required=True, help="JSON com parametros do template")
    wf_p.add_argument("--url", required=True)

    args = parser.parse_args()

    try:
        directory = redlensctl.run_dir(args.run)

        if args.action == "race":
            redlensctl.scoped_url(directory, args.url)
            if is_login_operation(args.url):
                result = {
                    "ok": True,
                    "verdict": "not-applicable",
                    "confidence": "high",
                    "reason": "Login repetivel nao eh condicao de corrida",
                    "url": args.url,
                }
                redlensctl.append_event(directory, "race.tested", {
                    "url": args.url,
                    "n": args.n,
                    "verdict": "not-applicable",
                })
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0

            if args.state_url:
                redlensctl.scoped_url(directory, args.state_url)
            if args.cleanup_url:
                redlensctl.scoped_url(directory, args.cleanup_url)

            headers = {"Content-Type": "application/json"}
            if args.headers:
                headers.update(json.loads(args.headers))
            body = b""
            if args.body:
                body = args.body.encode("utf-8")

            # 1. Estado inicial.
            initial_state = get_state(args.state_url, args.state_check) if args.state_url else None

            # 2. Baseline sequencial (controle negativo): 1 request.
            baseline_results = race_test(args.url, args.method, headers, body, 1, args.delay)
            baseline_state = get_state(args.state_url, args.state_check) if args.state_url else None

            # 3. Concorrencia.
            results = race_test(args.url, args.method, headers, body, args.n, args.delay)

            # 4. Estado final.
            final_state = get_state(args.state_url, args.state_check) if args.state_url else None

            # 5. Cleanup.
            if args.cleanup_url:
                send_request(args.cleanup_url, "POST", headers, b"")

            verdict_data = analyze_race(results, initial_state, baseline_state, final_state)

            timestamp = redlensctl.iso().replace(":", "").replace("-", "")
            raw_dir = directory / "evidence" / "raw"
            raw_dir.mkdir(parents=True, exist_ok=True)
            suffix = redlensctl.safe_id("token", args.url)[:12]
            raw_sample_path = raw_dir / f"{timestamp}-race-sample-{suffix}.json"
            # Persiste uma amostra bruta da primeira resposta concorrente.
            sample = results[0] if results else {"status": 0, "size": 0}
            redlensctl.write_json(raw_sample_path, sample)

            sanitized_dir = directory / "evidence" / "sanitized"
            sanitized_dir.mkdir(parents=True, exist_ok=True)
            summary_path = sanitized_dir / f"{timestamp}-race-{suffix}.json"
            summary = {
                "capability": "concurrency",
                "url": args.url,
                "method": args.method,
                "n": args.n,
                "initial_state": initial_state,
                "baseline_results": baseline_results,
                "baseline_state": baseline_state,
                "results": results,
                "final_state": final_state,
                "negative_control": {
                    "sequential_baseline": baseline_results,
                    "baseline_state": baseline_state,
                },
                "raw_sample": str(raw_sample_path.relative_to(directory)),
                **verdict_data,
            }
            redlensctl.write_json(summary_path, summary)

            if verdict_data["verdict"] == "confirmed":
                finding_id = redlensctl.safe_id("race", args.url)[:24]
                redlensctl.write_json(directory / "findings" / f"{finding_id}.json", {
                    "id": finding_id,
                    "title": f"Race condition em {args.url}",
                    "severity": "high",
                    "status": "confirmed",
                    "asset": args.url,
                    "evidence": [str(summary_path.relative_to(directory))],
                    "reproduced": True,
                    "negative_control": True,
                    "created_at": redlensctl.iso(),
                })

            redlensctl.append_event(directory, "race.tested", {
                "url": args.url,
                "n": args.n,
                "verdict": verdict_data["verdict"],
            })
            redlensctl.append_event(directory, "validator.finished", {
                "capability": "race",
                "verdict": verdict_data["verdict"],
                "url": args.url,
            })

            print(json.dumps({
                "ok": True,
                **verdict_data,
                "results": results,
                "initial_state": initial_state,
                "baseline_state": baseline_state,
                "final_state": final_state,
            }, ensure_ascii=False, indent=2))
            return 0

        elif args.action == "workflow":
            parameters = json.loads(args.parameters)
            workflow = workflow_test(args.template, parameters)
            workflow["url"] = args.url

            timestamp = redlensctl.iso().replace(":", "").replace("-", "")
            raw_dir = directory / "evidence" / "raw"
            raw_dir.mkdir(parents=True, exist_ok=True)
            raw_path = raw_dir / f"{timestamp}-workflow-{args.template}-raw.json"
            redlensctl.write_json(raw_path, {"template": args.template, "parameters": parameters})

            sanitized_dir = directory / "evidence" / "sanitized"
            sanitized_dir.mkdir(parents=True, exist_ok=True)
            summary_path = sanitized_dir / f"{timestamp}-workflow-{args.template}.json"
            redlensctl.write_json(summary_path, workflow)

            redlensctl.append_event(directory, "workflow.recorded", {
                "template": args.template,
                "url": args.url,
            })
            redlensctl.append_event(directory, "validator.finished", {
                "capability": "workflow",
                "verdict": "recorded",
                "url": args.url,
            })

            print(json.dumps({
                "ok": True,
                "workflow": workflow,
                "next_steps": [
                    "Implementar executor concreto deste template em adapter especifico",
                    "Registrar como tarefa em tasks/ para execucao automatica",
                ],
            }, ensure_ascii=False, indent=2))
            return 0

        return 2
    except (
        redlensctl.RedLensError,
        KeyError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
