#!/usr/bin/env python3
"""Restricted Playwright worker executed inside the Kali container."""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from cloakbrowser import launch as launch_cloakbrowser


def allowed(url: str, config: dict) -> bool:
    parsed = urlsplit(url)
    if parsed.scheme in {"data", "blob", "about"}:
        return True
    host = (parsed.hostname or "").lower()
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if parsed.scheme not in config["allowed_schemes"] or port not in config["allowed_ports"]:
        return False
    for entry in config["allowed_domains"]:
        if entry.startswith("*.") and host.endswith("." + entry[2:]):
            return True
        if host == entry:
            return True
    return False


def sanitized_url(url: str) -> str:
    """Keep paths and query keys for inventory, never query values."""
    parsed = urlsplit(url)
    query = "&".join(f"{key}=" for key, _ in parse_qsl(parsed.query, keep_blank_values=True))
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))


def run(config: dict, output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    state = Path(config["state"])
    backend = "cloakbrowser"
    requests: list[dict] = []
    responses: list[dict] = []
    websockets: list[str] = []
    browser = launch_cloakbrowser(headless=True, humanize=True)
    try:
        context_args = {}
        if state.is_file():
            context_args["storage_state"] = str(state)
        context = browser.new_context(**context_args)
        page = context.new_page()

        def capture_request(request):
            if allowed(request.url, config) and len(requests) < 250:
                requests.append({"method": request.method, "url": sanitized_url(request.url)})

        def capture_response(response):
            if allowed(response.url, config) and len(responses) < 250:
                content_type = response.headers.get("content-type", "").split(";", 1)[0]
                responses.append({
                    "url": sanitized_url(response.url),
                    "status": response.status,
                    "content_type": content_type,
                })

        def capture_websocket(websocket):
            if allowed(websocket.url, config) and len(websockets) < 50:
                websockets.append(sanitized_url(websocket.url))

        def route_handler(route):
            if allowed(route.request.url, config):
                route.continue_()
            else:
                route.abort("blockedbyclient")

        page.route("**/*", route_handler)
        page.on("request", capture_request)
        page.on("response", capture_response)
        page.on("websocket", capture_websocket)
        response = page.goto(config["url"], wait_until="commit", timeout=30000)
        page.wait_for_function('document.readyState == "complete"', timeout=30000)
        if config["action"] == "form":
            for field in config["fields"]:
                page.fill(field["selector"], field["value"])
            page.click(config["submit_selector"])
            time.sleep(min(int(config.get("wait_ms", 1000)), 10000) / 1000)
        html = page.content()
        page.screenshot(path=str(output / "page.png"), full_page=True)
        (output / "page.html").write_text(html, encoding="utf-8")
        context.storage_state(path=str(state))
        try:
            scripts = page.eval_on_selector_all("script[src]", "nodes => nodes.map(node => node.src)")
        except Exception:
            scripts = []
        discovered_urls = sorted({
            item["url"] for item in requests if item["url"].startswith(("http://", "https://"))
        } | {sanitized_url(item) for item in scripts if allowed(item, config)})
        lower_html = html.lower()
        challenge_markers = ("captcha", "turnstile", "just a moment", "checking your browser")
        challenge = next((marker for marker in challenge_markers if marker in lower_html), None)
        (output / "network.json").write_text(json.dumps({
            "requests": requests,
            "responses": responses,
            "websockets": sorted(set(websockets)),
        }, ensure_ascii=False, indent=2), encoding="utf-8")
        (output / "inventory.json").write_text(json.dumps({
            "urls": discovered_urls,
            "scripts": sorted({sanitized_url(item) for item in scripts if allowed(item, config)}),
        }, ensure_ascii=False, indent=2), encoding="utf-8")
        metadata = {
            "initial_url": config["url"],
            "final_url": page.url,
            "status": response.status if response else None,
            "title": page.title(),
            "action": config["action"],
            "backend": backend,
            "role": config.get("role", "default"),
            "request_count": len(requests),
            "response_count": len(responses),
            "websocket_count": len(websockets),
            "requires_human_intervention": bool(challenge),
            "challenge_reason": challenge,
        }
        (output / "metadata.json").write_text(
            json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        context.close()
    finally:
        browser.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text(encoding="utf-8"))
    run(config, Path(args.output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
