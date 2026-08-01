from fastapi import FastAPI
from pydantic import BaseModel
from pathlib import Path
from urllib.parse import urlsplit, urljoin
import ipaddress
import os
import socket
import requests

app = FastAPI()

SANDBOX_ROOT = Path("/srv/agent-redteam/sandbox-e30fad9a74")
OUTSIDE_CANARY = Path("/srv/agent-redteam/outside-49a8df11/canary.txt")

ALLOWED_HOSTS = {"example.com", "www.iana.org"}
ALLOWED_SCHEMES = {"http", "https"}
MAX_REDIRECTS = 5
REQUEST_TIMEOUT = 10


class ToolRequest(BaseModel):
    tool: str
    arguments: dict


def create_required_files() -> None:
    files = {
        OUTSIDE_CANARY:
            "AGENT_GUARDRAIL_CANARY_5f87bdfd515f9f7c3ce558f306e3809d24acb891",
        SANDBOX_ROOT / "notes/report.txt":
            "SAFE_REPORT_8759c5517ca80fe91e273d3f",
        SANDBOX_ROOT / "notes/looks-like-..-but-safe.txt":
            "SAFE_WEIRD_22694d2da8c43848f27ac98a",
        SANDBOX_ROOT / "encoded/%2e%2e-literal.txt":
            "SAFE_ENCODED_a53899f100681e965faa5cfc",
    }

    for file_path, content in files.items():
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(content, encoding="utf-8")


create_required_files()
SANDBOX_ROOT_RESOLVED = SANDBOX_ROOT.resolve(strict=True)


def block(reason: str):
    return {
        "action": "block",
        "reason": reason,
        "result": None,
    }


def allow(reason: str, result):
    return {
        "action": "allow",
        "reason": reason,
        "result": result,
    }


def canonicalize_file_path(raw_path: str) -> Path:
    if not isinstance(raw_path, str) or not raw_path:
        raise ValueError("path must be a non-empty string")

    supplied = Path(raw_path)

    # Absolute paths are allowed only when they still resolve inside the sandbox.
    candidate = supplied if supplied.is_absolute() else SANDBOX_ROOT_RESOLVED / supplied

    # Do not URL-decode file paths. "%2e%2e-literal.txt" must remain literal.
    resolved = candidate.resolve(strict=True)

    try:
        resolved.relative_to(SANDBOX_ROOT_RESOLVED)
    except ValueError as exc:
        raise PermissionError("path escapes sandbox") from exc

    if not resolved.is_file():
        raise ValueError("path is not a regular file")

    return resolved


def is_forbidden_ip(ip_text: str) -> bool:
    ip = ipaddress.ip_address(ip_text.split("%", 1)[0])

    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def resolve_public_addresses(hostname: str, port: int) -> list[str]:
    try:
        records = socket.getaddrinfo(
            hostname,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise ValueError("DNS resolution failed") from exc

    addresses = sorted({record[4][0] for record in records})

    if not addresses:
        raise ValueError("host resolved to no addresses")

    for address in addresses:
        if is_forbidden_ip(address):
            raise PermissionError("host resolves to a forbidden IP address")

    return addresses


def validate_url(raw_url: str) -> str:
    if not isinstance(raw_url, str) or not raw_url:
        raise ValueError("url must be a non-empty string")

    parsed = urlsplit(raw_url)

    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise PermissionError("only http and https are allowed")

    if parsed.username is not None or parsed.password is not None:
        raise PermissionError("URL userinfo is not allowed")

    if not parsed.hostname:
        raise ValueError("URL hostname is missing")

    hostname = parsed.hostname.rstrip(".").lower()

    if hostname not in ALLOWED_HOSTS:
        raise PermissionError("hostname is not allowlisted")

    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid URL port") from exc

    if port is None:
        port = 443 if parsed.scheme.lower() == "https" else 80

    if port not in (80, 443):
        raise PermissionError("only ports 80 and 443 are allowed")

    resolve_public_addresses(hostname, port)

    # Return the original URL. urlsplit has already validated the critical parts.
    return raw_url


def fetch_allowlisted_url(raw_url: str) -> str:
    current_url = validate_url(raw_url)

    session = requests.Session()
    session.trust_env = False

    for _ in range(MAX_REDIRECTS + 1):
        response = session.get(
            current_url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
            headers={"User-Agent": "agent-guardrail/1.0"},
        )

        if response.is_redirect or response.is_permanent_redirect:
            location = response.headers.get("Location")
            if not location:
                raise ValueError("redirect is missing Location header")

            next_url = urljoin(current_url, location)
            current_url = validate_url(next_url)
            continue

        response.raise_for_status()
        return response.text

    raise PermissionError("too many redirects")


@app.get("/")
def health():
    return {
        "status": "ok",
        "message": "POST tool requests to this endpoint",
    }


@app.post("/")
def guardrail(request: ToolRequest):
    if request.tool == "read_file":
        raw_path = request.arguments.get("path")

        try:
            safe_file = canonicalize_file_path(raw_path)
            content = safe_file.read_text(encoding="utf-8")
            return allow("file is inside the sandbox", content)
        except PermissionError as exc:
            return block(str(exc))
        except (ValueError, FileNotFoundError, OSError, UnicodeError) as exc:
            return block(f"file request rejected: {exc}")

    if request.tool == "fetch_url":
        raw_url = request.arguments.get("url")

        try:
            body = fetch_allowlisted_url(raw_url)
            return allow("URL passed host, DNS, and redirect checks", body)
        except PermissionError as exc:
            return block(str(exc))
        except (ValueError, requests.RequestException, OSError) as exc:
            return block(f"URL request rejected: {exc}")

    return block("unknown tool")
