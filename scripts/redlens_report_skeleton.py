#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a RedLens professional report skeleton")
    parser.add_argument("--state", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    state = Path(args.state)
    engagement = read_json(state / "engagement.json")
    findings = read_jsonl(state / "findings.jsonl")
    evidence = read_jsonl(state / "evidence_manifest.jsonl")
    coverage = read_json(state / "coverage.json") if (state / "coverage.json").exists() else {"gaps": []}

    lines = [
        "# Penetration Test Report",
        "",
        f"**Target:** {engagement.get('target_name', '')}",
        f"**Mode:** {engagement.get('assessment_mode', '')}",
        f"**Target Type:** {engagement.get('target_type', '')}",
        "",
        "## Executive Summary",
        "",
        "Write the leadership narrative here.",
        "",
        "## Authorization, Scope, And Constraints",
        "",
        "## Methodology",
        "",
        "## Findings Summary",
        "",
        "| ID | Severity | Confidence | Title |",
        "| --- | --- | --- | --- |",
    ]
    for finding in findings:
        lines.append(f"| {finding.get('id', '')} | {finding.get('severity', '')} | {finding.get('confidence', '')} | {finding.get('title', '')} |")
    lines += ["", "## Attack Chain Narrative", "", "## Detailed Findings", ""]
    for finding in findings:
        lines += [
            f"### {finding.get('id', '')}: {finding.get('title', '')}",
            "",
            f"**Severity:** {finding.get('severity', '')}",
            f"**Confidence:** {finding.get('confidence', '')}",
            "",
            "#### Business Impact",
            finding.get("business_impact", ""),
            "",
            "#### Remediation",
            finding.get("remediation", ""),
            "",
        ]
    lines += ["## Coverage And Gaps", ""]
    for gap in coverage.get("gaps", []):
        lines.append(f"- {gap}")
    lines += [
        "",
        "## Evidence Artifact Index",
        "",
        "| ID | Finding | Type | Path | SHA256 | Redaction |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for artifact in evidence:
        lines.append(
            f"| {artifact.get('id', '')} | {artifact.get('finding_id', '')} | {artifact.get('artifact_type', '')} | "
            f"{artifact.get('path', '')} | {artifact.get('sha256', '')} | {artifact.get('redaction_status', '')} |"
        )
    lines += ["", "## Remediation Roadmap", "", "## Retest Checklist", "", "## Appendices", ""]

    out = Path(args.out)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {out}")


if __name__ == "__main__":
    main()
