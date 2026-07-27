#!/usr/bin/env python3
"""Email inbox adapter for confirming signup links and extracting tokens.

Modos suportados:
  - mailinator: usa Mailinator API publica (inbox) para ler emails de confirmacao
  - guerrillamail: usa GuerrillaMail API para criar caixa temporaria
  - file: le um arquivo de email local (email emulated / debug)

Fluxo:
  1. Cria caixa postal temporaria (ou usa a fornecida)
  2. Executa acao que dispara o email (ex: signup)
  3. Polling ate o email chegar
  4. Extrai link de confirmacao / token do HTML do email
  5. Retorna o link ou token para uso no teste autenticado
"""

from __future__ import annotations

import argparse
import html.parser
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))

import redlensctl  # noqa: E402


SUPPORTED_PROVIDERS = {"mailinator", "guerrillamail", "file"}
DEFAULT_POLL_INTERVAL = 5  # segundos entre polls
DEFAULT_MAX_POLLS = 24      # max 2 minutos de polling


def _iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _now_ts() -> int:
    return int(time.time())


def _warn(msg: str) -> None:
    """Log warning to stderr (no _warn dependency)."""
    print(f"[email-safe] WARN: {msg}", file=sys.stderr)


def _debug(msg: str) -> None:
    """Log debug to stderr."""
    print(f"[email-safe] DEBUG: {msg}", file=sys.stderr)


# ─── Mailinator ──────────────────────────────────────────────────────────────

MAILINATOR_API = "https://api.mailinator.com/v2"


def mailinator_inbox(email: str) -> list[dict]:
    """Lista mensagens na inbox do Mailinator.

    O dominio deve ser mailinator.com ou um dos dominios alternativos.
    Retorna lista de {subject, from, id, seconds_ago, ...}.
    """
    local_part = email.split("@")[0]
    domain = email.split("@")[1] if "@" in email else "mailinator.com"
    url = f"{MAILINATOR_API}/domains/{domain}/inboxes/{local_part}"
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data.get("msgs", [])
    except (urllib.error.HTTPError, urllib.error.URLError, json.JSONDecodeError) as exc:
        _warn(f"Mailinator inbox error: {exc}")
        return []


def mailinator_read_msg(msg_id: str, domain: str = "mailinator.com") -> str | None:
    """Le o corpo HTML de uma mensagem especifica do Mailinator."""
    url = f"{MAILINATOR_API}/domains/{domain}/messages/{msg_id}"
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        parts = data.get("data", {}).get("parts", [])
        for part in parts:
            if part.get("headers", {}).get("content-type", "").startswith("text/html"):
                return part.get("body")
        # fallback: first text part
        for part in parts:
            body = part.get("body", "")
            if body:
                return body
        return data.get("data", {}).get("raw_text", "")
    except (urllib.error.HTTPError, urllib.error.URLError, json.JSONDecodeError) as exc:
        _warn(f"Mailinator read error: {exc}")
        return None


def mailinator_delete_inbox(email: str) -> bool:
    """Apaga inbox do Mailinator."""
    local_part = email.split("@")[0]
    domain = email.split("@")[1] if "@" in email else "mailinator.com"
    try:
        req = urllib.request.Request(
            f"{MAILINATOR_API}/inboxes/{local_part}",
            method="DELETE",
        )
        with urllib.request.urlopen(req, timeout=10):
            return True
    except Exception:
        return False


# ─── GuerrillaMail ───────────────────────────────────────────────────────────

GUERRILLA_API = "https://api.guerrillamail.com/ajax.php"
GUERRILLA_SESSION: dict = {}


def guerrillamail_create_inbox() -> dict:
    """Cria uma caixa postal temporaria no GuerrillaMail."""
    params = urllib.parse.urlencode([
        ("f", "get_email_address"),
        ("ip", ""),
        ("agent", "RedLens"),
    ])
    try:
        req = urllib.request.Request(f"{GUERRILLA_API}?{params}")
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        GUERRILLA_SESSION.update(data)
        return data  # {email_addr, alias, email_timestamp, sid_token}
    except (urllib.error.URLError, json.JSONDecodeError) as exc:
        raise redlensctl.RedLensError(f"GuerrillaMail create inbox failed: {exc}")


def guerrillamail_check_inbox(sid_token: str, seq: int = 0) -> list[dict]:
    """Verifica emails na caixa do GuerrillaMail."""
    params = urllib.parse.urlencode([
        ("f", "check_email"),
        ("sid_token", sid_token),
        ("seq", str(seq)),
    ])
    try:
        req = urllib.request.Request(f"{GUERRILLA_API}?{params}")
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data.get("list", [])  # [{mail_id, mail_from, mail_subject, mail_excerpt, ...}]
    except (urllib.error.URLError, json.JSONDecodeError) as exc:
        _warn(f"GuerrillaMail check error: {exc}")
        return []


def guerrillamail_fetch_email(sid_token: str, mail_id: str) -> str | None:
    """Obtem o corpo completo de um email do GuerrillaMail."""
    params = urllib.parse.urlencode([
        ("f", "fetch_email"),
        ("sid_token", sid_token),
        ("email_id", mail_id),
    ])
    try:
        req = urllib.request.Request(f"{GUERRILLA_API}?{params}")
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        # Retorna mail_body - pode ser HTML ou texto
        return data.get("mail_body") or data.get("mail_excerpt", "")
    except (urllib.error.URLError, json.JSONDecodeError) as exc:
        _warn(f"GuerrillaMail fetch error: {exc}")
        return None


def guerrillamail_forget(sid_token: str) -> bool:
    """Remove caixa do GuerrillaMail."""
    params = urllib.parse.urlencode([
        ("f", "forget_email"),
        ("sid_token", sid_token),
    ])
    try:
        req = urllib.request.Request(f"{GUERRILLA_API}?{params}")
        with urllib.request.urlopen(req, timeout=10):
            return True
    except Exception:
        return False


# ─── Extração de links de confirmação ────────────────────────────────────────


class LinkExtractor(html.parser.HTMLParser):
    """Extrai todos os hrefs de tags <a> no HTML."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "a":
            for name, value in attrs:
                if name == "href" and value:
                    self.links.append(value)


def extract_confirmation_links(html_body: str) -> list[str]:
    """Extrai links de confirmacao do HTML.

    Procura por:
    - hrefs em tags <a>
    - URLs contendo confirm, verify, activate, signup, magic-link, token
    - Plain URLs no texto
    """
    parser = LinkExtractor()
    parser.feed(html_body)
    all_links = parser.links

    # Filtra links que parecem ser de confirmacao
    confirm_keywords = re.compile(
        r"(confirm|verify|activate|magic.?link|signup|email.?confirm|auth/callback|access.?token|#access_token)",
        re.IGNORECASE,
    )
    candidates = [link for link in all_links if confirm_keywords.search(link)]
    if not candidates:
        # fallback: qualquer link que contenha token ou hash
        token_like = re.compile(r"(token=|code=|hash=|key=|#(access_token|refresh_token))")
        candidates = [link for link in all_links if token_like.search(link)]
    if not candidates:
        # ultimo fallback: devolve todos os links
        candidates = all_links

    # Expande URLs relativas
    # (sem base URL, retornamos como foram encontrados)
    return candidates


def extract_from_text(text_body: str) -> list[str]:
    """Extrai URLs de um corpo de texto plano."""
    url_pattern = re.compile(r"https?://[^\s<>\"']+")
    return url_pattern.findall(text_body)


# ─── Função principal ────────────────────────────────────────────────────────


def wait_for_confirmation_link(
    email: str,
    provider: str = "mailinator",
    poll_interval: int = DEFAULT_POLL_INTERVAL,
    max_polls: int = DEFAULT_MAX_POLLS,
    expected_subject: str | None = None,
    sid_token: str | None = None,
) -> dict:
    """Faz polling ate encontrar email de confirmacao e extrai o link.

    Returns:
        {
            "ok": bool,
            "link": str | None,
            "token": str | None,
            "email_found": bool,
            "polls": int,
            "subject": str | None,
            "from": str | None,
            "body_excerpt": str | None,
        }
    """
    result: dict = {
        "ok": False,
        "link": None,
        "token": None,
        "email_found": False,
        "polls": 0,
        "subject": None,
        "from": None,
        "body_excerpt": None,
    }

    for poll_num in range(1, max_polls + 1):
        time.sleep(poll_interval)
        result["polls"] = poll_num

        messages = []
        if provider == "mailinator":
            messages = mailinator_inbox(email)
        elif provider == "guerrillamail":
            if not sid_token:
                continue
            messages = guerrillamail_check_inbox(sid_token)
        elif provider == "file":
            # file mode: single pass, no polling
            break

        if not messages:
            _debug(f"Poll {poll_num}/{max_polls}: nenhum email ainda")
            continue

        # Filtra por assunto se esperado
        if expected_subject:
            filtered = [
                m for m in messages
                if expected_subject.lower() in (m.get("subject", "") or "").lower()
            ]
            if filtered:
                messages = filtered
            else:
                continue

        # Pega a mensagem mais recente
        msg = messages[0]
        result["email_found"] = True
        result["subject"] = msg.get("subject")
        result["from"] = msg.get("from") or msg.get("mail_from")

        # Obtem corpo
        body = None
        if provider == "mailinator":
            msg_id = msg.get("id")
            if msg_id:
                domain = email.split("@")[1] if "@" in email else "mailinator.com"
                body = mailinator_read_msg(msg_id, domain)
        elif provider == "guerrillamail":
            mail_id = msg.get("mail_id")
            if mail_id and sid_token:
                body = guerrillamail_fetch_email(sid_token, mail_id)

        if body:
            result["body_excerpt"] = body[:500]

            # Extrai links de confirmacao
            links = extract_confirmation_links(body)
            if not links:
                links = extract_from_text(body)

            if links:
                result["link"] = links[0]
                # Tenta extrair token do link
                token_match = re.search(
                    r"(?:token|access_token|code|hash|key)=([^&]+)", links[0]
                )
                if token_match:
                    result["token"] = urllib.parse.unquote(token_match.group(1))
                # Tenta extrair de fragmento JWT (#access_token=...)
                frag_match = re.search(r"#(?:access_token|id_token)=([^&]+)", links[0])
                if frag_match:
                    result["token"] = urllib.parse.unquote(frag_match.group(1))

            result["ok"] = True
        break

    return result


# ─── CLI ─────────────────────────────────────────────────────────────────────


def cmd_create_inbox(args: argparse.Namespace) -> dict:
    """Cria caixa postal temporaria."""
    if args.provider == "guerrillamail":
        inbox = guerrillamail_create_inbox()
        return {
            "ok": True,
            "provider": "guerrillamail",
            "email": inbox.get("email_addr"),
            "alias": inbox.get("alias"),
            "sid_token": inbox.get("sid_token"),
            "timestamp": inbox.get("email_timestamp"),
        }
    elif args.provider == "mailinator":
        # Mailinator nao precisa criar inbox - qualquer email @mailinator.com funciona
        email = args.email or f"redlens-{_now_ts()}@mailinator.com"
        return {
            "ok": True,
            "provider": "mailinator",
            "email": email,
            "note": "Mailinator inbox existe automaticamente ao receber primeiro email",
        }
    raise redlensctl.RedLensError(f"Provider {args.provider} nao suporta create-inbox")


def cmd_wait_link(args: argparse.Namespace) -> dict:
    """Aguarda email de confirmacao e extrai link."""
    if not args.email:
        raise redlensctl.RedLensError("--email é obrigatorio para wait-link")
    result = wait_for_confirmation_link(
        email=args.email,
        provider=args.provider,
        poll_interval=args.poll_interval,
        max_polls=args.max_polls,
        expected_subject=args.subject,
        sid_token=args.sid_token,
    )
    return result


def cmd_check(args: argparse.Namespace) -> dict:
    """Verifica inbox una vez (sem polling)."""
    if args.provider == "mailinator":
        messages = mailinator_inbox(args.email)
        return {
            "ok": True,
            "provider": "mailinator",
            "email": args.email,
            "messages": len(messages),
            "inbox": messages,
        }
    elif args.provider == "guerrillamail":
        if not args.sid_token:
            raise redlensctl.RedLensError("--sid_token obrigatorio para guerrillamail")
        messages = guerrillamail_check_inbox(args.sid_token)
        return {
            "ok": True,
            "provider": "guerrillamail",
            "messages": len(messages),
            "inbox": messages,
        }
    raise redlensctl.RedLensError(f"Provider {args.provider} nao suporta check")


def cmd_cleanup(args: argparse.Namespace) -> dict:
    """Limpa recursos (apaga inbox)."""
    if args.provider == "mailinator":
        deleted = mailinator_delete_inbox(args.email)
        return {"ok": deleted, "provider": "mailinator", "email": args.email, "deleted": deleted}
    elif args.provider == "guerrillamail":
        if not args.sid_token:
            raise redlensctl.RedLensError("--sid_token obrigatorio")
        forgotten = guerrillamail_forget(args.sid_token)
        return {"ok": forgotten, "provider": "guerrillamail", "forgotten": forgotten}
    raise redlensctl.RedLensError(f"Provider {args.provider} nao suporta cleanup")


def main() -> int:
    parser = argparse.ArgumentParser(prog="email-safe", description="Gerenciamento de email temporario para pentest")
    parser.add_argument("--run", help="Run ID (opcional, para registrar evidencia)")
    sub = parser.add_subparsers(dest="action", required=True)

    # create-inbox
    ci = sub.add_parser("create-inbox", help="Cria caixa postal temporaria")
    ci.add_argument("--provider", choices=SUPPORTED_PROVIDERS, default="mailinator")
    ci.add_argument("--email", help="Email para usar (se nao gerar automaticamente)")

    # wait-link
    wl = sub.add_parser("wait-link", help="Aguarda email e extrai link de confirmacao")
    wl.add_argument("--email", required=True)
    wl.add_argument("--provider", choices=SUPPORTED_PROVIDERS, default="mailinator")
    wl.add_argument("--poll-interval", type=int, default=DEFAULT_POLL_INTERVAL)
    wl.add_argument("--max-polls", type=int, default=DEFAULT_MAX_POLLS)
    wl.add_argument("--subject", help="Filtrar por assunto esperado")
    wl.add_argument("--sid-token", help="SID token do GuerrillaMail")

    # check
    ck = sub.add_parser("check", help="Verifica inbox uma vez")
    ck.add_argument("--email", required=True)
    ck.add_argument("--provider", choices=SUPPORTED_PROVIDERS, default="mailinator")
    ck.add_argument("--sid-token")

    # cleanup
    cl = sub.add_parser("cleanup", help="Apaga inbox temporaria")
    cl.add_argument("--provider", choices=SUPPORTED_PROVIDERS, default="mailinator")
    cl.add_argument("--email")
    cl.add_argument("--sid-token")

    try:
        args = parser.parse_args()
    except SystemExit as exc:
        return int(exc.code) if exc.code is not None else 2

    try:
        result = None
        if args.action == "create-inbox":
            result = cmd_create_inbox(args)
        elif args.action == "wait-link":
            result = cmd_wait_link(args)
        elif args.action == "check":
            result = cmd_check(args)
        elif args.action == "cleanup":
            result = cmd_cleanup(args)
        else:
            raise redlensctl.RedLensError(f"Unknown action: {args.action}")

        # Registra evidencia se run foi fornecido
        if args.run and result:
            try:
                directory = redlensctl.run_dir(args.run)
                timestamp = _iso()
                raw_dir = directory / "evidence" / "raw"
                raw_dir.mkdir(parents=True, exist_ok=True)
                evidence_path = raw_dir / f"{timestamp}-email-{args.action}.json"
                redlensctl.write_json(evidence_path, result)

                sanitized_dir = directory / "evidence" / "sanitized"
                sanitized_dir.mkdir(parents=True, exist_ok=True)
                summary_path = sanitized_dir / f"{timestamp}-email-{args.action}.json"
                # Sanitiza: remove corpo do email da evidencia publica
                public_result = {k: v for k, v in result.items() if k != "body_excerpt"}
                redlensctl.write_json(summary_path, public_result)

                redlensctl.append_event(directory, f"email.{args.action}", {
                    "provider": args.provider,
                    "email": args.email or result.get("email"),
                    "ok": result.get("ok", False),
                })
            except Exception as exc:
                _warn(f"Nao foi possivel registrar evidencia: {exc}")

        print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
        return 0 if result.get("ok", False) else 2

    except (redlensctl.RedLensError, json.JSONDecodeError, KeyError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
