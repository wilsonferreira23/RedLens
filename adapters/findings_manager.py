#!/usr/bin/env python3
"""Findings manager: schema completo com CVSS, CWE, OWASP, cadeia, reteste.

Schema obrigatorio por finding:
- ID, titulo, categoria
- CWE/OWASP
- Severidade e CVSS
- Confianca
- Ativos afetados
- Precondicoes
- Impacto tecnico
- Impacto de negocio
- Root cause
- Passos de reproducao
- Evidencias
- Controle negativo
- Validacao independente
- Correcao
- Reteste
- Relacoes de cadeia
- Status

Findings criticos ou altos exigem:
- prova direta
- reproducao
- controle negativo
- segunda validacao independente
- evidencia sanitizada
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))

import redlensctl  # noqa: E402


REQUIRED_FIELDS = [
    "id", "title", "category", "severity", "cvss_score", "cvss_vector",
    "cwe", "owasp", "confidence",
    "affected_assets", "preconditions",
    "technical_impact", "business_impact",
    "root_cause", "reproduction_steps",
    "evidence", "negative_control", "independent_validation",
    "remediation", "retest_checklist",
    "chain_relations", "status",
]


CWE_CATALOG = {
    "CWE-79": "Cross-site Scripting (XSS)",
    "CWE-89": "SQL Injection",
    "CWE-78": "OS Command Injection",
    "CWE-94": "Code Injection",
    "CWE-77": "Command Injection",
    "CWE-22": "Path Traversal",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-611": "XML External Entity (XXE)",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-862": "Missing Authorization",
    "CWE-863": "Incorrect Authorization",
    "CWE-639": "Authorization Bypass Through User-Controlled Key (IDOR/BOLA)",
    "CWE-285": "Improper Authorization",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-915": "Improperly Controlled Modification of Dynamically-Determined Object Attributes (Mass Assignment)",
    "CWE-200": "Exposure of Sensitive Information",
    "CWE-522": "Insufficiently Protected Credentials",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-326": "Insufficient Encryption Strength",
    "CWE-319": "Cleartext Transmission of Sensitive Information",
    "CWE-942": "Permissive Cross-domain Policy",
    "CWE-770": "Allocation of Resources Without Limits",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-209": "Information Exposure Through Error Message",
    "CWE-362": "Concurrent Execution using Shared Resource (Race Condition)",
    "CWE-384": "Session Fixation",
    "CWE-613": "Insufficient Session Expiration",
}


OWASP_TOP_10 = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery (SSRF)",
}


CATEGORY_TO_CWE_OWASP = {
    "sqli": ("CWE-89", "A03"),
    "xss": ("CWE-79", "A03"),
    "cmdi": ("CWE-78", "A03"),
    "ssti": ("CWE-94", "A03"),
    "traversal": ("CWE-22", "A03"),
    "ssrf": ("CWE-918", "A10"),
    "xxe": ("CWE-611", "A05"),
    "nosqli": ("CWE-89", "A03"),
    "csrf": ("CWE-352", "A01"),
    "bola": ("CWE-639", "A01"),
    "bfla": ("CWE-285", "A01"),
    "authn": ("CWE-522", "A07"),
    "authz": ("CWE-862", "A01"),
    "mass-assignment": ("CWE-915", "A04"),
    "upload": ("CWE-434", "A04"),
    "graphql": ("CWE-862", "A01"),
    "websocket": ("CWE-862", "A01"),
    "grpc": ("CWE-200", "A05"),
    "concurrency": ("CWE-362", "A04"),
    "race": ("CWE-362", "A04"),
    "deserialization": ("CWE-502", "A08"),
    "info": ("CWE-200", "A05"),
}


SEVERITY_CVSS = {
    "info": (0.0, 3.9),
    "low": (0.1, 3.9),
    "medium": (4.0, 6.9),
    "high": (7.0, 8.9),
    "critical": (9.0, 10.0),
}


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def compute_cvss_from_severity(severity: str) -> tuple[float, str]:
    if severity not in SEVERITY_CVSS:
        raise redlensctl.RedLensError(f"Severidade invalida: {severity}")
    base, top = SEVERITY_CVSS[severity]
    score = round((base + top) / 2, 1)
    vector = f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" if score >= 7.0 else "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
    return score, vector


def get_cwe_owasp_for_category(category: str) -> tuple[str, str]:
    return CATEGORY_TO_CWE_OWASP.get(category, ("CWE-1000", "A04"))


def build_finding(
    category: str,
    title: str,
    severity: str,
    asset: str,
    technical_impact: str,
    business_impact: str,
    root_cause: str,
    reproduction_steps: list[str],
    evidence: list[str],
    remediation: str,
    confidence: str = "high",
    cwe: str | None = None,
    owasp: str | None = None,
    preconditions: list[str] | None = None,
    negative_control: str | None = None,
    independent_validation: str | None = None,
    retest_checklist: list[str] | None = None,
    chain_relations: list[str] | None = None,
    status: str = "observation",
    affected_assets: list[str] | None = None,
) -> dict:
    """Constroi um finding completo com todos os campos obrigatorios."""
    if severity not in SEVERITY_CVSS:
        raise redlensctl.RedLensError(f"Severidade invalida: {severity}")

    if cwe is None or owasp is None:
        default_cwe, default_owasp = get_cwe_owasp_for_category(category)
        cwe = cwe or default_cwe
        owasp = owasp or default_owasp

    cvss_score, cvss_vector = compute_cvss_from_severity(severity)

    finding_id = redlensctl.safe_id("finding", category, title, asset)

    finding = {
        "id": finding_id,
        "title": title,
        "category": category,
        "severity": severity,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "cwe": cwe,
        "cwe_name": CWE_CATALOG.get(cwe, "Unknown"),
        "owasp": owasp,
        "owasp_name": OWASP_TOP_10.get(owasp, "Unknown"),
        "confidence": confidence,
        "affected_assets": affected_assets or [asset],
        "preconditions": preconditions or [],
        "technical_impact": technical_impact,
        "business_impact": business_impact,
        "root_cause": root_cause,
        "reproduction_steps": reproduction_steps,
        "evidence": evidence,
        "negative_control": negative_control or "",
        "independent_validation": independent_validation or "",
        "remediation": remediation,
        "retest_checklist": retest_checklist or [
            f"Aplicar remediacao: {remediation}",
            "Reexecutar reproducao apos fix",
            "Confirmar via segundo metodo independente",
        ],
        "chain_relations": chain_relations or [],
        "status": status,
        "created_at": iso_now(),
        "updated_at": iso_now(),
        "schema_version": "1.0",
    }

    if severity in {"high", "critical"} and status == "confirmed":
        missing = []
        if not finding["reproduction_steps"]:
            missing.append("reproduction_steps")
        if not finding["negative_control"]:
            missing.append("negative_control")
        if not finding["independent_validation"]:
            missing.append("independent_validation")
        if not finding["evidence"]:
            missing.append("evidence")
        if missing:
            raise redlensctl.RedLensError(
                f"Finding {severity} confirmado requer: {', '.join(missing)}"
            )

    return finding


def validate_finding(finding: dict) -> list[str]:
    """Retorna lista de campos faltando/incorretos."""
    errors = []
    for field in REQUIRED_FIELDS:
        if field not in finding:
            errors.append(f"campo obrigatorio ausente: {field}")
    if "severity" in finding and finding["severity"] not in SEVERITY_CVSS:
        errors.append(f"severidade invalida: {finding['severity']}")
    if finding.get("cwe") not in CWE_CATALOG:
        errors.append(f"CWE desconhecido: {finding.get('cwe')}")
    if finding.get("owasp") not in OWASP_TOP_10:
        errors.append(f"OWASP desconhecido: {finding.get('owasp')}")
    if finding.get("severity") in {"high", "critical"} and finding.get("status") == "confirmed":
        if not finding.get("reproduction_steps"):
            errors.append("alta/critico confirmado requer reproduction_steps")
        if not finding.get("negative_control"):
            errors.append("alta/critico confirmado requer negative_control")
        if not finding.get("independent_validation"):
            errors.append("alta/critico confirmado requer independent_validation")
    return errors


def save_finding(directory: Path, finding: dict) -> Path:
    errors = validate_finding(finding)
    if errors:
        raise redlensctl.RedLensError(f"Finding invalido: {'; '.join(errors)}")
    finding["updated_at"] = iso_now()
    path = directory / "findings" / f"{finding['id']}.json"
    redlensctl.write_json(path, finding)
    return path


def link_chain(directory: Path, finding_id: str, related_id: str) -> None:
    """Vincula dois findings em uma cadeia."""
    path = directory / "findings" / f"{finding_id}.json"
    if not path.is_file():
        raise redlensctl.RedLensError(f"Finding nao encontrado: {finding_id}")
    finding = json.loads(path.read_text(encoding="utf-8"))
    related_path = directory / "findings" / f"{related_id}.json"
    if not related_path.is_file():
        raise redlensctl.RedLensError(f"Finding relacionado nao encontrado: {related_id}")
    related = json.loads(related_path.read_text(encoding="utf-8"))

    if related_id not in finding.get("chain_relations", []):
        finding.setdefault("chain_relations", []).append(related_id)
    if finding_id not in related.get("chain_relations", []):
        related.setdefault("chain_relations", []).append(finding_id)

    finding["updated_at"] = iso_now()
    related["updated_at"] = iso_now()
    redlensctl.write_json(path, finding)
    redlensctl.write_json(related_path, related)


def generate_findings_report(directory: Path) -> dict:
    """Gera sumario de findings para o relatorio."""
    findings = []
    for path in sorted((directory / "findings").glob("*.json")):
        try:
            findings.append(json.loads(path.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, OSError):
            continue

    by_severity: dict[str, int] = {s: 0 for s in SEVERITY_CVSS}
    by_category: dict[str, int] = {}
    by_cwe: dict[str, int] = {}
    by_owasp: dict[str, int] = {}
    by_status: dict[str, int] = {}

    for f in findings:
        sev = f.get("severity", "info")
        by_severity[sev] = by_severity.get(sev, 0) + 1
        cat = f.get("category", "unknown")
        by_category[cat] = by_category.get(cat, 0) + 1
        cwe = f.get("cwe", "unknown")
        by_cwe[cwe] = by_cwe.get(cwe, 0) + 1
        owasp = f.get("owasp", "unknown")
        by_owasp[owasp] = by_owasp.get(owasp, 0) + 1
        status = f.get("status", "observation")
        by_status[status] = by_status.get(status, 0) + 1

    return {
        "total": len(findings),
        "by_severity": by_severity,
        "by_category": by_category,
        "by_cwe": by_cwe,
        "by_owasp": by_owasp,
        "by_status": by_status,
        "high_critical_count": by_severity.get("high", 0) + by_severity.get("critical", 0),
        "findings": findings,
    }


def main() -> int:
    parser = argparse.ArgumentParser(prog="findings-manager")
    sub = parser.add_subparsers(dest="action", required=True)

    build_p = sub.add_parser("build")
    build_p.add_argument("--run", required=True)
    build_p.add_argument("--category", required=True)
    build_p.add_argument("--title", required=True)
    build_p.add_argument("--severity", choices=list(SEVERITY_CVSS), required=True)
    build_p.add_argument("--asset", required=True)
    build_p.add_argument("--technical-impact", required=True)
    build_p.add_argument("--business-impact", required=True)
    build_p.add_argument("--root-cause", required=True)
    build_p.add_argument("--remediation", required=True)
    build_p.add_argument("--reproduction-steps", required=True, help="JSON list")
    build_p.add_argument("--evidence", required=True, help="JSON list")
    build_p.add_argument("--status", choices=("observation", "confirmed"), default="observation")
    build_p.add_argument("--preconditions", help="JSON list")
    build_p.add_argument("--negative-control")
    build_p.add_argument("--independent-validation")
    build_p.add_argument("--retest-checklist", help="JSON list")
    build_p.add_argument("--affected-assets", help="JSON list")

    validate_p = sub.add_parser("validate")
    validate_p.add_argument("--run", required=True)
    validate_p.add_argument("--finding", required=True)

    link_p = sub.add_parser("link-chain")
    link_p.add_argument("--run", required=True)
    link_p.add_argument("--finding", required=True)
    link_p.add_argument("--related", required=True)

    report = sub.add_parser("report")
    report.add_argument("--run", required=True)

    args = parser.parse_args()
    try:
        directory = redlensctl.run_dir(args.run)

        if args.action == "build":
            finding = build_finding(
                category=args.category,
                title=args.title,
                severity=args.severity,
                asset=args.asset,
                technical_impact=args.technical_impact,
                business_impact=args.business_impact,
                root_cause=args.root_cause,
                reproduction_steps=json.loads(args.reproduction_steps),
                evidence=json.loads(args.evidence),
                remediation=args.remediation,
                preconditions=json.loads(args.preconditions) if args.preconditions else None,
                negative_control=args.negative_control,
                independent_validation=args.independent_validation,
                retest_checklist=json.loads(args.retest_checklist) if args.retest_checklist else None,
                status=args.status,
                affected_assets=json.loads(args.affected_assets) if args.affected_assets else None,
            )
            path = save_finding(directory, finding)
            redlensctl.append_event(directory, "finding.recorded", {"id": finding["id"], "severity": finding["severity"]})
            print(json.dumps({"ok": True, "finding_id": finding["id"], "path": str(path.relative_to(directory))}, ensure_ascii=False, indent=2))
            return 0

        elif args.action == "validate":
            path = directory / "findings" / f"{args.finding}.json"
            if not path.is_file():
                print(json.dumps({"ok": False, "error": f"finding nao encontrado: {args.finding}"}, ensure_ascii=False), file=sys.stderr)
                return 2
            finding = json.loads(path.read_text(encoding="utf-8"))
            errors = validate_finding(finding)
            print(json.dumps({"ok": len(errors) == 0, "errors": errors}, ensure_ascii=False, indent=2))
            return 0 if not errors else 2

        elif args.action == "link-chain":
            link_chain(directory, args.finding, args.related)
            print(json.dumps({"ok": True, "linked": [args.finding, args.related]}, ensure_ascii=False, indent=2))
            return 0

        elif args.action == "report":
            summary = generate_findings_report(directory)
            print(json.dumps(summary, ensure_ascii=False, indent=2))
            return 0

    except (
        redlensctl.RedLensError,
        KeyError,
        ValueError,
        json.JSONDecodeError,
        OSError,
    ) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())