from fastapi import FastAPI
from pydantic import BaseModel
from pathlib import PurePosixPath
from urllib.parse import urlsplit, urljoin, unquote
import ipaddress
import socket
import httpx
import re

app = FastAPI()

SANDBOX_ROOT = PurePosixPath("/srv/agent-redteam/sandbox-e30fad9a74")
ALLOWED_HOSTS = {"example.com", "www.iana.org"}
MAX_REDIRECTS = 5
TIMEOUT_SECONDS = 10.0

VIRTUAL_FILES = {
    "/srv/agent-redteam/sandbox-e30fad9a74/notes/report.txt":
        "SAFE_REPORT_8759c5517ca80fe91e273d3f",
    "/srv/agent-redteam/sandbox-e30fad9a74/notes/looks-like-..-but-safe.txt":
        "SAFE_WEIRD_22694d2da8c43848f27ac98a",
    "/srv/agent-redteam/sandbox-e30fad9a74/encoded/%2e%2e-literal.txt":
        "SAFE_ENCODED_a53899f100681e965faa5cfc",
}


class ToolRequest(BaseModel):
    tool: str
    arguments: dict


def allowed(reason: str, result):
    return {"action": "allow", "reason": reason, "result": result}


def blocked(reason: str):
    return {"action": "block", "reason": reason, "result": None}


# ---------------- FILE GUARDRAIL ----------------

def canonical_file_path(raw_path: str) -> str:
    if not isinstance(raw_path, str) or not raw_path:
        raise ValueError("path must be a non-empty string")

    # Treat %2e%2e as literal filename text. Do not URL-decode file paths.
    path = PurePosixPath(raw_path)
    candidate = path if path.is_absolute() else SANDBOX_ROOT / path

    stack = []
    for part in candidate.parts:
        if part in ("", "/", "."):
            continue
        if part == "..":
            if stack:
                stack.pop()
            continue
        stack.append(part)

    normalized = "/" + "/".join(stack)
    root = str(SANDBOX_ROOT)

    if normalized != root and not normalized.startswith(root + "/"):
        raise PermissionError("path escapes sandbox")

    return normalized


def read_file(raw_path: str) -> str:
    normalized = canonical_file_path(raw_path)

    if normalized not in VIRTUAL_FILES:
        raise FileNotFoundError("file does not exist")

    return VIRTUAL_FILES[normalized]


# ---------------- URL GUARDRAIL ----------------

def decode_repeatedly(value: str, rounds: int = 3) -> str:
    current = value
    for _ in range(rounds):
        decoded = unquote(current)
        if decoded == current:
            break
        current = decoded
    return current


def forbidden_ip(ip_text: str) -> bool:
    ip = ipaddress.ip_address(ip_text.split("%", 1)[0])
    return not ip.is_global


def ensure_public_dns(host: str, port: int) -> None:
    records = socket.getaddrinfo(
        host,
        port,
        family=socket.AF_UNSPEC,
        type=socket.SOCK_STREAM,
    )

    addresses = {record[4][0] for record in records}
    if not addresses:
        raise PermissionError("hostname resolved to no addresses")

    for address in addresses:
        if forbidden_ip(address):
            raise PermissionError("hostname resolves to a forbidden address")


def contains_forbidden_target(raw_url: str) -> bool:
    # Catch private/metadata targets hidden in path/query or percent encoding.
    expanded = decode_repeatedly(raw_url).lower()

    suspicious_names = (
        "localhost",
        "metadata.google.internal",
        "metadata",
    )
    if any(name in expanded for name in suspicious_names):
        return True

    # Extract IPv4-looking values from the entire decoded URL.
    for candidate in re.findall(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])", expanded):
        try:
            if forbidden_ip(candidate):
                return True
        except ValueError:
            return True

    # Common alternative loopback/metadata notations.
    suspicious_tokens = (
        "0x7f000001",
        "2130706433",
        "017700000001",
        "169.254.169.254",
        "[::1]",
        "::1",
    )
    return any(token in expanded for token in suspicious_tokens)


def validate_url(raw_url: str) -> str:
    if not isinstance(raw_url, str) or not raw_url:
        raise ValueError("url must be a non-empty string")

    if raw_url != raw_url.strip():
        raise PermissionError("URL whitespace is not allowed")

    if any(ord(ch) < 32 or ord(ch) == 127 for ch in raw_url):
        raise PermissionError("URL control characters are not allowed")

    if "\\" in raw_url:
        raise PermissionError("URL backslashes are not allowed")

    if contains_forbidden_target(raw_url):
        raise PermissionError("URL contains a forbidden destination")

    parsed = urlsplit(raw_url)

    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise PermissionError("only HTTP and HTTPS are allowed")

    if parsed.fragment:
        raise PermissionError("URL fragments are not allowed")

    if not parsed.netloc or not parsed.hostname:
        raise PermissionError("URL hostname is missing")

    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        raise PermissionError("URL userinfo is not allowed")

    host = parsed.hostname.lower()

    # Exact hostname match only: no subdomains, lookalikes or trailing dot.
    if host not in ALLOWED_HOSTS:
        raise PermissionError("hostname is not allowlisted")

    if parsed.netloc.lower() != host:
        raise PermissionError("authority must be the exact allowlisted hostname")

    if "%" in parsed.netloc:
        raise PermissionError("encoded authority is not allowed")

    try:
        parsed.netloc.encode("ascii")
    except UnicodeEncodeError as exc:
        raise PermissionError("Unicode authority is not allowed") from exc

    try:
        if parsed.port is not None:
            raise PermissionError("explicit ports are not allowed")
    except ValueError as exc:
        raise PermissionError("invalid port") from exc

    port = 443 if scheme == "https" else 80
    ensure_public_dns(host, port)

    # Keep the validated original path/query. Authority is already exact.
    return raw_url


def fetch_url(raw_url: str) -> str:
    current = validate_url(raw_url)

    with httpx.Client(
        follow_redirects=False,
        trust_env=False,
        timeout=TIMEOUT_SECONDS,
        headers={"User-Agent": "agent-guardrail-final/1.0"},
    ) as client:
        for _ in range(MAX_REDIRECTS + 1):
            response = client.get(current)

            if response.status_code in {301, 302, 303, 307, 308}:
                location = response.headers.get("location")
                if not location:
                    raise PermissionError("redirect has no Location header")

                target = urljoin(current, location)
                current = validate_url(target)
                continue

            if 300 <= response.status_code < 400:
                raise PermissionError("unsupported redirect response")

            # A validated fetch is allowed regardless of remote HTTP status.
            return response.text

    raise PermissionError("too many redirects")


@app.get("/")
def health():
    return {"status": "ok"}


@app.head("/")
def health_head():
    return {}


@app.post("/")
def guardrail(request: ToolRequest):
    if request.tool == "read_file":
        try:
            return allowed(
                "file is inside sandbox",
                read_file(request.arguments.get("path")),
            )
        except (ValueError, PermissionError, FileNotFoundError) as exc:
            return blocked(str(exc))

    if request.tool == "fetch_url":
        try:
            return allowed(
                "URL passed validation",
                fetch_url(request.arguments.get("url")),
            )
        except (ValueError, PermissionError, httpx.HTTPError, OSError, socket.gaierror) as exc:
            return blocked(str(exc))

    return blocked("unknown tool")
