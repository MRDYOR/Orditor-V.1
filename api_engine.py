#!/usr/bin/env python3
"""
Orditor API Analyzer
---------------------
Static analysis pass over Python API server code (Flask / FastAPI), looking for
the checklist items a real API security review starts with: auth gaps on
sensitive routes, hardcoded secrets, permissive CORS, injection via string-built
queries/commands, debug mode left on, verbose error leakage, sensitive data
logged, and missing rate limiting.

Same caveat as the contract analyzer: this is regex + light block-scoping, not a
full control-flow/taint analysis (e.g. Bandit, Semgrep with real dataflow). It
catches known patterns; it will have false positives/negatives, especially
around indirect auth checks (a decorator defined in another file, an auth check
buried three calls deep). Read every finding, don't just count them.

Usage:
    python3 api_analyzer.py <path-to-server.py> [--out findings.json]
"""

import re
import sys
import json
import argparse
from dataclasses import dataclass, field, asdict
from typing import List, Optional

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    category: str
    line: Optional[int]
    route: Optional[str]
    description: str
    recommendation: str
    snippet: str = ""


@dataclass
class Route:
    method: str
    path: str
    func_name: str
    decorator_line: int
    def_line: int
    end_line: int
    decorators: List[str] = field(default_factory=list)


SENSITIVE_PATH_RE = re.compile(
    r"(admin|delete|remove|withdraw|transfer|payout|refund|secret|config|internal|"
    r"debug|key|credential|token|impersonate|sudo|override|export|dump)", re.I
)

AUTH_GUARD_RE = re.compile(
    r"login_required|requires_auth|require_auth|auth_required|jwt_required|"
    r"Depends\s*\(\s*(get_current_user|require_|verify_|auth)|api_key_required|"
    r"check_auth|authenticate|permission_required|roles_required", re.I
)

SECRET_PATTERNS = [
    (re.compile(r"sk_live_[A-Za-z0-9]{16,}"), "Stripe live secret key"),
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "OpenAI-style API key"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key ID"),
    (re.compile(r"-----BEGIN (RSA |EC )?PRIVATE KEY-----"), "PEM private key"),
    (re.compile(r"(?i)\b(api_key|apikey|secret_key|secret|password|token)\s*=\s*[\"'][A-Za-z0-9_\-\.]{12,}[\"']"),
     "Hardcoded credential-shaped literal"),
]


def strip_comments(line: str) -> str:
    # crude: drop trailing # comment not inside a string (good enough for this heuristic pass)
    if "#" in line and '"' not in line.split("#")[0] and "'" not in line.split("#")[0]:
        return line.split("#")[0]
    return line


def extract_routes(lines: List[str]) -> List[Route]:
    routes = []
    route_deco_re = re.compile(
        r'@(?:app|router|api|bp|blueprint)\.(route|get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']'
    )
    n = len(lines)
    i = 0
    while i < n:
        m = route_deco_re.search(lines[i])
        if m:
            deco_start = i
            method = m.group(1).upper() if m.group(1) != "route" else "ROUTE"
            path = m.group(2)
            decorators = [lines[i].strip()]
            j = i + 1
            # gather any stacked decorators (e.g. @login_required, @limiter.limit(...))
            while j < n and lines[j].strip().startswith("@"):
                decorators.append(lines[j].strip())
                j += 1
            # the def line
            def_line_idx = None
            k = j
            while k < n and k < j + 3:
                if re.match(r"\s*(async\s+)?def\s+(\w+)\s*\(", lines[k]):
                    def_line_idx = k
                    break
                k += 1
            if def_line_idx is not None:
                func_m = re.match(r"\s*(async\s+)?def\s+(\w+)\s*\(", lines[def_line_idx])
                func_name = func_m.group(2)
                def_indent = len(lines[def_line_idx]) - len(lines[def_line_idx].lstrip())
                end = def_line_idx
                p = def_line_idx + 1
                while p < n:
                    stripped = lines[p].strip()
                    if stripped == "":
                        p += 1
                        continue
                    indent = len(lines[p]) - len(lines[p].lstrip())
                    if indent <= def_indent:
                        break
                    end = p
                    p += 1
                routes.append(Route(
                    method=method, path=path, func_name=func_name,
                    decorator_line=deco_start + 1, def_line=def_line_idx + 1,
                    end_line=end + 1, decorators=decorators
                ))
                i = end
        i += 1
    return routes


def analyze(source: str, filename: str = "server.py") -> List[Finding]:
    lines = source.splitlines()
    routes = extract_routes(lines)
    findings: List[Finding] = []
    fid = 0

    def new_id():
        nonlocal fid
        fid += 1
        return f"ORD-API-{fid:03d}"

    # 1. Debug mode enabled
    for i, line in enumerate(lines, 1):
        if re.search(r"debug\s*=\s*True", line):
            findings.append(Finding(
                id=new_id(), title="Debug mode enabled", severity="Critical",
                category="Configuration", line=i, route=None,
                description="`debug=True` was found. In Flask specifically, this enables the Werkzeug interactive debugger, which allows arbitrary Python code execution from anyone who can trigger an unhandled exception and reach the debugger endpoint.",
                recommendation="Never run with debug mode enabled in a deployed environment. Use an environment variable gated to local development only, and confirm it defaults to off.",
                snippet=line.strip()
            ))

    # 2. Hardcoded secrets
    for i, line in enumerate(lines, 1):
        clean = strip_comments(line)
        for pattern, label in SECRET_PATTERNS:
            if pattern.search(clean):
                sev = "Critical" if label != "Hardcoded credential-shaped literal" else "High"
                findings.append(Finding(
                    id=new_id(), title=f"Possible hardcoded secret ({label})", severity=sev,
                    category="Secrets Management", line=i, route=None,
                    description=f"A pattern matching '{label}' was found directly in source. Hardcoded secrets end up in version control history permanently, even if removed later, and are visible to anyone with repo access.",
                    recommendation="Move this to an environment variable or a secrets manager, rotate the exposed credential immediately (treat it as compromised), and scrub it from git history if already committed.",
                    snippet=re.sub(r"[A-Za-z0-9_\-\.]{8,}", "***REDACTED***", clean.strip())
                ))
                break

    # 3. CORS wildcard
    for i, line in enumerate(lines, 1):
        if re.search(r'origins\s*=\s*\[?\s*["\']\*["\']', line) or re.search(r'Access-Control-Allow-Origin["\']?\s*[,:]\s*["\']\*["\']', line):
            window = "\n".join(lines[max(0, i - 3):min(len(lines), i + 3)])
            has_credentials = bool(re.search(r"allow_credentials\s*=\s*True|supports_credentials\s*=\s*True", window))
            findings.append(Finding(
                id=new_id(), title="Wildcard CORS origin" + (" combined with credentials" if has_credentials else ""),
                severity="High" if has_credentials else "Medium",
                category="CORS", line=i, route=None,
                description="CORS is configured to allow any origin (`*`)." + (
                    " This is combined with `allow_credentials`/`supports_credentials = True`, which most browsers will actually reject — but some clients and proxies don't enforce that combination, and it signals the policy wasn't scoped deliberately."
                    if has_credentials else " Any website can make cross-origin requests to this API from a user's browser."
                ),
                recommendation="Scope `allow_origins`/`origins` to a specific known list of domains rather than `*`, especially for any endpoint that reads authenticated session state.",
                snippet=line.strip()
            ))

    # 4. Sensitive routes without a detected auth guard
    for r in routes:
        if not SENSITIVE_PATH_RE.search(r.path) and not SENSITIVE_PATH_RE.search(r.func_name):
            continue
        deco_text = " ".join(r.decorators)
        body = "\n".join(lines[r.def_line - 1:r.end_line])
        has_decorator_guard = bool(AUTH_GUARD_RE.search(deco_text))
        has_inline_guard = bool(
            re.search(r"request\.headers\.get\(\s*[\"']Authorization", body, re.I) or
            re.search(r"if\s+not\s+\w*(auth|token|api_key)", body, re.I) or
            AUTH_GUARD_RE.search(body)
        )
        if has_decorator_guard or has_inline_guard:
            continue
        findings.append(Finding(
            id=new_id(), title=f"Sensitive route `{r.method} {r.path}` has no visible auth check",
            severity="Critical", category="Access Control", line=r.decorator_line, route=f"{r.method} {r.path}",
            description=f"The route `{r.path}` (handler `{r.func_name}`) looks privileged based on its path/name, but no authentication decorator (e.g. `login_required`, `Depends(get_current_user)`) or inline auth check was detected.",
            recommendation="Add an authentication/authorization check before this handler runs — a decorator, a FastAPI dependency, or an explicit header/token check at the top of the function.",
            snippet=deco_text
        ))

    # 5. SQL / command injection via string interpolation
    exec_call_re = re.compile(r"\.(execute|executemany)\s*\(\s*(f[\"']|[\"'].*%s.*[\"']\s*%|[\"'].*\{.*\}.*[\"']\.format)")
    fstring_sql_re = re.compile(r"\.(execute|executemany)\s*\(\s*f[\"']")
    concat_sql_re = re.compile(r"\.(execute|executemany)\s*\(\s*[\"'].*[\"']\s*\+")
    shell_true_re = re.compile(r"(subprocess\.(call|run|Popen)|os\.system|os\.popen)\s*\(.*\bshell\s*=\s*True")
    fstring_shell_re = re.compile(r"(os\.system|os\.popen)\s*\(\s*f[\"']")

    # Track variables built from an f-string/concat containing SQL keywords, so we
    # catch the (very common) two-step pattern: `q = f"SELECT ... {x}"` then
    # `cur.execute(q)` — not just an inline f-string passed directly.
    sql_keyword_re = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE)\b", re.I)
    tainted_sql_vars = {}  # varname -> (line_no, snippet)
    for i, line in enumerate(lines, 1):
        assign_m = re.match(r"\s*(\w+)\s*=\s*(f[\"'].*[\"']|[\"'].*[\"']\s*\+.*|[\"'].*[\"']\.format\(.*\))\s*$", line)
        if assign_m and sql_keyword_re.search(line) and ("{" in line or "+" in line or ".format(" in line):
            tainted_sql_vars[assign_m.group(1)] = (i, line.strip())

    for i, line in enumerate(lines, 1):
        if fstring_sql_re.search(line) or concat_sql_re.search(line):
            findings.append(Finding(
                id=new_id(), title="SQL query built via string interpolation/concatenation",
                severity="Critical", category="Injection", line=i, route=None,
                description="A database `.execute(...)` call appears to build its query with an f-string or string concatenation rather than parameter binding. If any part of that string comes from user input, this is SQL injection.",
                recommendation="Use parameterized queries: `cursor.execute(\"SELECT * FROM t WHERE id = %s\", (user_id,))` instead of interpolating values into the query string.",
                snippet=line.strip()
            ))
        else:
            exec_var_m = re.search(r"\.(?:execute|executemany)\s*\(\s*(\w+)\s*\)", line)
            if exec_var_m and exec_var_m.group(1) in tainted_sql_vars:
                assign_line, assign_snippet = tainted_sql_vars[exec_var_m.group(1)]
                findings.append(Finding(
                    id=new_id(), title="SQL query built via string interpolation/concatenation",
                    severity="Critical", category="Injection", line=assign_line, route=None,
                    description=f"Variable `{exec_var_m.group(1)}` is built with an f-string/concatenation containing SQL keywords, then passed to `.execute()` on line {i}. If any interpolated part comes from user input, this is SQL injection — splitting the query build and the execute call across lines doesn't change that.",
                    recommendation="Use parameterized queries: `cursor.execute(\"SELECT * FROM t WHERE id = %s\", (user_id,))` instead of interpolating values into the query string.",
                    snippet=assign_snippet
                ))
        if shell_true_re.search(line) or fstring_shell_re.search(line):
            findings.append(Finding(
                id=new_id(), title="Shell command built from a variable/f-string with shell=True",
                severity="Critical", category="Injection", line=i, route=None,
                description="A subprocess/os call runs with `shell=True` (or `os.system`/`os.popen`) alongside an f-string or otherwise dynamic command. If any part comes from user input, this is command injection.",
                recommendation="Avoid `shell=True`; pass arguments as a list to `subprocess.run([...])`. If shell features are unavoidable, strictly allowlist and escape any user-derived input.",
                snippet=line.strip()
            ))

    # 6. Verbose error leakage
    for i, line in enumerate(lines, 1):
        if re.search(r"return\s+.*\bstr\s*\(\s*e\s*\)", line) or re.search(r"traceback\.format_exc\(\)", line):
            window = "\n".join(lines[max(0, i - 4):i])
            if re.search(r"except\s+Exception", window):
                findings.append(Finding(
                    id=new_id(), title="Exception detail returned directly in API response",
                    severity="Medium", category="Error Handling", line=i, route=None,
                    description="An exception handler returns the raw exception message (or a full traceback) to the caller. This can leak internals: file paths, library versions, query fragments, or stack context useful for further attack.",
                    recommendation="Log the full exception server-side; return a generic error message and an opaque error/reference ID to the caller.",
                    snippet=line.strip()
                ))

    # 7. Sensitive data logged
    for i, line in enumerate(lines, 1):
        if re.search(r"(print|log(ger)?\.\w+)\s*\(.*\b(request\.headers|request\.json|password|authorization)\b", line, re.I):
            findings.append(Finding(
                id=new_id(), title="Potentially sensitive data written to logs", severity="Medium",
                category="Data Handling", line=i, route=None,
                description="A log/print statement includes request headers, the raw request body, or a variable named like a credential. Auth headers, tokens, and passwords ending up in logs is a common way secrets leak long after the original request.",
                recommendation="Redact or omit authorization headers, tokens, and password fields before logging. Log identifiers (user ID, request ID), not raw credential-bearing payloads.",
                snippet=line.strip()
            ))

    # 8. No rate limiting detected anywhere in the file
    has_rate_limit = bool(re.search(r"flask_limiter|slowapi|Limiter\s*\(|@limiter\.limit|RateLimit", source))
    if routes and not has_rate_limit:
        findings.append(Finding(
            id=new_id(), title="No rate limiting detected in this file", severity="Low",
            category="Denial of Service", line=None, route=None,
            description=f"{len(routes)} route(s) were found and no rate-limiting library or decorator (e.g. flask-limiter, slowapi) was detected in this file. This may be handled elsewhere (a gateway, reverse proxy), but isn't visible from the source reviewed.",
            recommendation="Confirm rate limiting is enforced somewhere in the request path — application-level or at the infrastructure/gateway layer — especially for any endpoint that triggers paid work, on-chain calls, or expensive computation.",
            snippet=""
        ))

    # 9. Cookie without secure flag
    for i, line in enumerate(lines, 1):
        if re.search(r"SESSION_COOKIE_SECURE\s*=\s*False", line) or re.search(r"set_cookie\([^)]*secure\s*=\s*False", line):
            findings.append(Finding(
                id=new_id(), title="Session cookie explicitly marked not secure", severity="Medium",
                category="Transport Security", line=i, route=None,
                description="A cookie is explicitly configured without the `Secure` flag, meaning it can be sent over plain HTTP, not just HTTPS.",
                recommendation="Set the Secure flag on any session/auth cookie (and HttpOnly, SameSite as appropriate) unless there's a specific documented reason not to.",
                snippet=line.strip()
            ))

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.line or 0))
    return findings, routes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("server", help="Path to .py API server file")
    ap.add_argument("--out", default=None, help="Write findings JSON here")
    args = ap.parse_args()

    with open(args.server, "r", encoding="utf-8") as fh:
        src = fh.read()

    findings, routes = analyze(src, filename=args.server)
    result = {
        "file": args.server,
        "route_count": len(routes),
        "routes": [{"method": r.method, "path": r.path, "func": r.func_name} for r in routes],
        "finding_count": len(findings),
        "by_severity": {
            sev: len([f for f in findings if f.severity == sev])
            for sev in SEVERITY_ORDER
        },
        "findings": [asdict(f) for f in findings],
    }
    out_text = json.dumps(result, indent=2)
    if args.out:
        with open(args.out, "w") as f:
            f.write(out_text)
        print(f"Wrote {len(findings)} findings ({len(routes)} routes scanned) to {args.out}")
    else:
        print(out_text)


if __name__ == "__main__":
    main()
