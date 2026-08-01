from fastapi import FastAPI
from pydantic import BaseModel
from pathlib import PurePosixPath
from urllib.parse import urlsplit, urljoin, unquote
import ipaddress
import socket
import httpx
import re
import dns.resolver

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
    try:
        ip = ipaddress.ip_address(ip_text.split("%", 1)[0])
        return not ip.is_global
    except ValueError:
        return True


def ensure_public_dns(host: str, port: int) -> None:
    try:
        # Use dnspython for more controlled resolution
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        
        # Query both A and AAAA records
        answers = []
        try:
            answers.extend(resolver.resolve(host, 'A'))
        except:
            pass
        try:
            answers.extend(resolver.resolve(host, 'AAAA'))
        except:
            pass
        
        if not answers:
            raise PermissionError("hostname resolved to no addresses")
            
        for answer in answers:
            ip_str = str(answer)
            if forbidden_ip(ip_str):
                raise PermissionError(f"hostname resolves to forbidden address: {ip_str}")
                
    except dns.resolver.NXDOMAIN:
        raise PermissionError("hostname does not exist")
    except dns.resolver.NoAnswer:
        raise PermissionError("hostname has no A/AAAA records")
    except dns.resolver.Timeout:
        raise PermissionError("DNS resolution timeout")
    except Exception as exc:
        raise PermissionError(f"DNS resolution failed: {exc}")


def contains_forbidden_target(raw_url: str) -> bool:
    # Only decode the URL for analysis, but keep the original for other checks
    expanded = decode_repeatedly(raw_url).lower()
    
    # Extract the hostname from the URL to avoid scanning path/query for hostnames
    try:
        parsed = urlsplit(raw_url)
        hostname = parsed.hostname
        if not hostname:
            return True  # Block if no hostname
        hostname = hostname.lower()
    except Exception:
        return True  # Block if parsing fails
    
    # Check for IP addresses in hostname
    ip_match = re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", hostname)
    if ip_match:
        try:
            if forbidden_ip(hostname):
                return True
        except ValueError:
            return True
    
    # Check for IPv6 in hostname
    if hostname.startswith('[') and hostname.endswith(']'):
        try:
            ip = ipaddress.ip_address(hostname[1:-1])
            if not ip.is_global:
                return True
        except ValueError:
            return True
    
    # Check for suspicious hostnames (exact match)
    suspicious_hostnames = {
        "localhost",
        "metadata.google.internal",
        "metadata",
        "169.254.169.254",
        "0.0.0.0",
        "127.0.0.1",
        "::1",
        "[::1]",
        "0x7f000001",
        "2130706433",
        "017700000001",
        "instance-data",
        "instance-data.ec2.internal",
        "169.254.169.254",
    }
    
    # Check exact hostname match
    if hostname in suspicious_hostnames:
        return True
    
    # Check for hostnames that end with suspicious domains
    for suspicious in suspicious_hostnames:
        if hostname.endswith('.' + suspicious):
            return True
    
    # Check for URL-encoded or alternative representations
    # These can bypass hostname checks
    if any(token in expanded for token in ["%2e", "%2E", "0x", "0X", "0177", "0169"]):
        # If we see encoding, decode and check again
        fully_decoded = unquote(expanded)
        try:
            parsed2 = urlsplit(fully_decoded)
            if parsed2.hostname and parsed2.hostname.lower() in suspicious_hostnames:
                return True
        except:
            pass
    
    # Check for DNS rebinding - resolve hostname now
    if not ip_match and not hostname.startswith('['):
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 3
            
            # Check A records
            try:
                answers = resolver.resolve(hostname, 'A')
                for answer in answers:
                    ip_str = str(answer)
                    if forbidden_ip(ip_str):
                        return True
            except:
                pass
                
            # Check AAAA records
            try:
                answers = resolver.resolve(hostname, 'AAAA')
                for answer in answers:
                    ip_str = str(answer)
                    if forbidden_ip(ip_str):
                        return True
            except:
                pass
        except:
            pass
    
    return False


def validate_url(raw_url: str, is_redirect: bool = False) -> str:
    if not isinstance(raw_url, str) or not raw_url:
        raise ValueError("url must be a non-empty string")

    if raw_url != raw_url.strip():
        raise PermissionError("URL whitespace is not allowed")

    if any(ord(ch) < 32 or ord(ch) == 127 for ch in raw_url):
        raise PermissionError("URL control characters are not allowed")

    if "\\" in raw_url:
        raise PermissionError("URL backslashes are not allowed")

    # Parse URL first to check hostname
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

    # For redirects, we need to re-validate the final host
    if is_redirect:
        # Re-check host against allowlist
        if host not in ALLOWED_HOSTS:
            raise PermissionError("redirect hostname is not allowlisted")
        
        # Re-check DNS resolution
        try:
            ensure_public_dns(host, 443 if scheme == "https" else 80)
        except PermissionError as exc:
            raise PermissionError(f"redirect DNS validation failed: {exc}")
    
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

    # Check for forbidden targets BEFORE DNS resolution
    if contains_forbidden_target(raw_url):
        raise PermissionError("URL contains a forbidden destination")
    
    # DNS resolution happens here for the initial request
    if not is_redirect:
        port = 443 if scheme == "https" else 80
        ensure_public_dns(host, port)

    # Keep the validated original path/query. Authority is already exact.
    return raw_url


def fetch_url(raw_url: str) -> str:
    current = validate_url(raw_url, is_redirect=False)

    with httpx.Client(
        follow_redirects=False,
        trust_env=False,
        timeout=TIMEOUT_SECONDS,
        headers={
            "User-Agent": "agent-guardrail-final/1.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        },
        max_redirects=0,  # We handle redirects manually
    ) as client:
        for redirect_count in range(MAX_REDIRECTS + 1):
            # Make the request
            response = client.get(current, follow_redirects=False)
            
            # Check for redirect status codes
            if response.status_code in {301, 302, 303, 307, 308}:
                location = response.headers.get("location")
                if not location:
                    raise PermissionError("redirect has no Location header")
                
                # Resolve relative redirects
                target = urljoin(current, location)
                
                # Re-validate the redirect target with is_redirect=True
                try:
                    current = validate_url(target, is_redirect=True)
                except (ValueError, PermissionError) as exc:
                    # Check if the redirect location itself is suspicious
                    # Some attacks use redirects to internal IPs
                    raise PermissionError(f"redirect validation failed: {exc}")
                
                continue
            
            # If it's a 3xx but not a recognized redirect, block it
            if 300 <= response.status_code < 400:
                raise PermissionError("unsupported redirect response")
            
            # If we got here, it's a final response (2xx, 4xx, 5xx)
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