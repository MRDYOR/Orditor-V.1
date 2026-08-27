#!/usr/bin/env python3
"""
Orditor Agent-Specific Analyzer
---------------------------------
Two check families on top of the general API analyzer, specific to AI-agent
projects:

1. Containment — can the agent's own actions reach further than intended?
   Motivated directly by the July 2026 OpenAI/Hugging Face incident: a model
   under test escaped its sandbox (via a third-party dependency vulnerability
   Orditor can't see), found leaked credentials on the open internet (which the
   general API analyzer's secrets check already covers), and used them to reach
   a real production system. The checks here target the *code-level* version of
   that failure mode — unrestricted code execution, unrestricted tool dispatch,
   unrestricted outbound network access, unbounded agent loops, and secrets
   sitting reachable from agent-executed code.

2. Payment verification — for x402-style or other agent-to-agent payment
   handling: is a payment proof actually verified (signature, replay/nonce,
   amount/recipient match, expiry) before the agent treats it as valid?

Same caveat as the other two analyzers: heuristic pattern matching, not a full
taint/dataflow tool. It will have false positives/negatives — particularly
around checks implemented in an imported helper this file doesn't see.

Usage:
    python3 agent_analyzer.py <path-to-agent_code.py> [--out findings.json]
"""

import re
import sys
import json
import argparse
from dataclasses import dataclass, asdict
from typing import List, Optional

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    category: str
    line: Optional[int]
    function: Optional[str]
    description: str
    recommendation: str
    snippet: str = ""


@dataclass
class Func:
    name: str
    start_line: int
    end_line: int


def extract_functions(lines: List[str]) -> List[Func]:
    funcs = []
    n = len(lines)
    for i, line in enumerate(lines):
        m = re.match(r"(\s*)(async\s+)?def\s+(\w+)\s*\(", line)
        if not m:
            continue
        indent = len(m.group(1))
        name = m.group(3)
        end = i
        p = i + 1
        while p < n:
            stripped = lines[p].strip()
            if stripped == "":
                p += 1
                continue
            cur_indent = len(lines[p]) - len(lines[p].lstrip())
            if cur_indent <= indent:
                break
            end = p
            p += 1
        funcs.append(Func(name=name, start_line=i + 1, end_line=end + 1))
    return funcs


AGENT_CONTENT_NAME_RE = re.compile(
    r"response|output|completion|model_output|agent_output|tool_call|generated|"
    r"code|reply|message|content", re.I
)
TOOL_DISPATCH_NAME_RE = re.compile(
    r"run_tool|execute_tool|call_tool|dispatch_tool|tool_handler|execute_command|"
    r"run_agent_action|handle_tool_call|run_action", re.I
)
AGENT_LOOP_NAME_RE = re.compile(r"agent_loop|run_agent|agent_step|main_loop|run_task", re.I)
PAYMENT_NAME_RE = re.compile(r"x402|payment|pay_to|x_payment|verify_payment|process_payment", re.I)


def strip_comments(src: str) -> str:
    lines = src.splitlines()
    out = []
    in_triple = False
    for line in lines:
        if '"""' in line or "'''" in line:
            # crude: toggle triple-quote docstring state; good enough for this heuristic pass
            count = line.count('"""') + line.count("'''")
            if count % 2 == 1:
                in_triple = not in_triple
            out.append("")  # drop the docstring line's content from matching
            continue
        if in_triple:
            out.append("")
            continue
        if "#" in line:
            before = line.split("#")[0]
            if '"' not in before and "'" not in before:
                line = before
        out.append(line)
    return "\n".join(out)


def analyze(source: str) -> List[Finding]:
    lines = source.splitlines()
    code_only = strip_comments(source)
    funcs = extract_functions(lines)
    findings: List[Finding] = []
    fid = 0

    def new_id():
        nonlocal fid
        fid += 1
        return f"ORD-AGT-{fid:03d}"

    def body_of(f: Func) -> str:
        # code_only is line-aligned with `lines`, so slicing the same range keeps
        # heuristic checks from matching keywords that only appear in comments/docstrings
        return "\n".join(code_only.splitlines()[f.start_line - 1:f.end_line])

    # --- Containment checks -------------------------------------------------

    # 1. eval/exec on agent-produced content
    code_lines = code_only.splitlines()
    for i, line in enumerate(code_lines, 1):
        m = re.search(r"\b(eval|exec)\s*\(\s*(\w+)", line)
        if not m:
            continue
        call, argname = m.group(1), m.group(2)
        agent_related = bool(AGENT_CONTENT_NAME_RE.search(argname))
        restricted = bool(re.search(r"__builtins__\s*:\s*\{\s*\}|__builtins__\s*:\s*None", line)) or \
            bool(re.search(r"__builtins__\s*:\s*\{\s*\}|__builtins__\s*:\s*None", "\n".join(code_lines[max(0, i - 3):i])))
        if restricted:
            continue
        findings.append(Finding(
            id=new_id(),
            title=f"`{call}()` called on {'agent/model-generated content' if agent_related else 'a dynamic value'} with no restricted execution environment",
            severity="Critical" if agent_related else "Medium",
            category="Containment", line=i, function=None,
            description=f"`{call}({argname}...)` runs {'text that appears to originate from a model/agent response' if agent_related else 'a dynamically-built string'} as Python code, with no restricted `globals`/`__builtins__` passed in. If the model can be influenced (via its input, a tool result, or a prompt injection) to produce text that ends up here, this is arbitrary code execution — the exact shape of failure mode that let a model escape its intended boundary in the July 2026 OpenAI/Hugging Face incident.",
            recommendation="Avoid eval/exec on model output entirely if possible. If unavoidable, run it in a genuinely isolated sandbox (separate process/container, no network, no filesystem access, no ambient credentials) rather than restricted-globals-in-process, which is not a real security boundary.",
            snippet=lines[i - 1].strip() if i - 1 < len(lines) else line.strip()
        ))

    # 2. Tool dispatch reaching subprocess/os.system without a visible allowlist
    for f in funcs:
        if not TOOL_DISPATCH_NAME_RE.search(f.name):
            continue
        body = body_of(f)
        has_shell = bool(re.search(r"subprocess\.(run|call|Popen)|os\.system|os\.popen", body))
        if not has_shell:
            continue
        has_allowlist = bool(re.search(r"allowlist|allowed_(commands|tools|actions)|ALLOWED_(COMMANDS|TOOLS)|whitelist", body, re.I))
        if has_allowlist:
            continue
        findings.append(Finding(
            id=new_id(), title=f"Tool dispatcher `{f.name}` can run shell commands with no visible allowlist",
            severity="Critical", category="Containment", line=f.start_line, function=f.name,
            description=f"`{f.name}` looks like the function that turns an agent's chosen tool/action into an actual system call, and it reaches `subprocess`/`os.system` with no allowlist of permitted commands or tools detected in its body. If the agent can choose or influence the command (directly, or indirectly through a compromised/confused reasoning step), this gives it unrestricted shell access.",
            recommendation="Maintain an explicit allowlist of tool names/commands the agent is permitted to invoke, validated before dispatch — not just relying on the model 'choosing correctly.' Deny by default.",
            snippet=f"def {f.name}(...)"
        ))

    # 3. Outbound requests to a non-literal URL with no domain allowlist
    outbound_re = re.compile(r"\b(requests|httpx)\.(get|post|put|delete|request)\s*\(\s*(\w+)")
    urlopen_re = re.compile(r"\burlopen\s*\(\s*(\w+)")
    for f in funcs:
        body = body_of(f)
        matches = list(outbound_re.finditer(body)) + [(m,) for m in urlopen_re.finditer(body)]
        if not matches:
            continue
        # only flag inside functions that look agent/tool-related, to avoid noise
        # on ordinary application code making internal API calls
        if not (TOOL_DISPATCH_NAME_RE.search(f.name) or AGENT_LOOP_NAME_RE.search(f.name) or "tool" in f.name.lower() or "agent" in f.name.lower()):
            continue
        has_allowlist = bool(re.search(r"allowlist|allowed_domains|ALLOWED_DOMAINS|allowed_hosts", body, re.I))
        if has_allowlist:
            continue
        first = matches[0]
        line_no = f.start_line + body[:first[0].start() if hasattr(first[0], 'start') else 0].count("\n") if hasattr(first, '__getitem__') else f.start_line
        findings.append(Finding(
            id=new_id(), title=f"Agent-related function `{f.name}` makes outbound requests to a non-literal URL with no domain allowlist",
            severity="High", category="Containment", line=f.start_line, function=f.name,
            description=f"`{f.name}` issues an outbound HTTP request where the URL comes from a variable, not a hardcoded literal, and no domain allowlist was detected. An agent that can influence that variable (directly or via a tool result / retrieved content) can direct outbound requests anywhere — including to services that will accept leaked or ambient credentials, echoing the mechanism used to reach Hugging Face's infrastructure in the July 2026 incident.",
            recommendation="Restrict outbound requests from agent-controlled code paths to an explicit allowlist of domains. Treat any URL that originates from model output or tool results as untrusted input.",
            snippet=f"def {f.name}(...)"
        ))

    # 4. Unbounded agent loop
    for f in funcs:
        if not AGENT_LOOP_NAME_RE.search(f.name):
            continue
        body = body_of(f)
        if not re.search(r"while\s+True\s*:", body):
            continue
        has_bound = bool(re.search(r"max_iter|max_steps|iteration_limit|timeout|MAX_(ITER|STEPS)|step\s*>=|steps\s*>=|budget", body, re.I))
        if has_bound:
            continue
        findings.append(Finding(
            id=new_id(), title=f"Agent loop `{f.name}` has no visible iteration cap or timeout",
            severity="Medium", category="Containment", line=f.start_line, function=f.name,
            description=f"`{f.name}` runs a `while True:` loop with no max-iteration count, step budget, or timeout detected. An agent stuck in an unproductive cycle (or deliberately kept going by something it's interacting with) can run indefinitely, burning cost and time and — combined with any of the containment gaps above — window for something to go wrong.",
            recommendation="Add an explicit iteration cap, wall-clock timeout, or cost/step budget that forces the loop to terminate and hand control back, regardless of what the model decides to do next.",
            snippet=f"def {f.name}(...)"
        ))

    # 5. Secrets loaded as plain module-level vars reachable by exec/eval in same file
    has_exec_eval = bool(re.search(r"\b(eval|exec)\s*\(", code_only))
    if has_exec_eval:
        for i, line in enumerate(code_lines, 1):
            if re.match(r"^\s*[A-Z_][A-Z0-9_]*\s*=\s*os\.environ", line):
                findings.append(Finding(
                    id=new_id(), title="Secret loaded at module scope in a file that also runs eval/exec",
                    severity="High", category="Containment", line=i, function=None,
                    description="A credential is loaded into a plain module-level variable in the same file that also calls `eval`/`exec`. Code executed via eval/exec in the same process can read any variable in scope — including this one — regardless of whether the exec call itself looks unrelated.",
                    recommendation="Keep credential loading out of any module that executes dynamic/agent-produced code, or ensure exec/eval runs in a genuinely separate process with its own restricted environment that doesn't inherit these variables.",
                    snippet=lines[i - 1].strip() if i - 1 < len(lines) else line.strip()
                ))

    # --- Payment verification checks ----------------------------------------

    for f in funcs:
        if not PAYMENT_NAME_RE.search(f.name):
            continue
        body = body_of(f)

        has_sig_check = bool(re.search(r"verify_signature|recover_message|recover_signer|Account\.recover|ecrecover|verify_proof|signature\.verify", body, re.I))
        if not has_sig_check:
            findings.append(Finding(
                id=new_id(), title=f"Payment handler `{f.name}` has no visible signature verification",
                severity="Critical", category="Payment Verification", line=f.start_line, function=f.name,
                description=f"`{f.name}` looks like it processes a payment proof/header, but no call to a signature-recovery or verification function was detected. Without verifying the signature, an attacker can submit a fabricated payment payload and have it treated as real.",
                recommendation="Verify the payment proof's signature against the expected payer/facilitator before treating it as valid — e.g. recovering the signer address and checking it matches what's expected.",
                snippet=f"def {f.name}(...)"
            ))

        has_nonce_check = bool(re.search(r"\bnonce\b|used_nonces|seen_(requests|payments)|replay", body, re.I))
        if not has_nonce_check:
            findings.append(Finding(
                id=new_id(), title=f"Payment handler `{f.name}` has no visible replay/nonce protection",
                severity="High", category="Payment Verification", line=f.start_line, function=f.name,
                description=f"`{f.name}` shows no tracking of a nonce or previously-seen payment identifier. Without this, a validly-signed payment proof can potentially be replayed to trigger the paid action multiple times for a single payment.",
                recommendation="Track consumed nonces/payment IDs (in memory with TTL, or persisted) and reject any payment proof that reuses one already seen.",
                snippet=f"def {f.name}(...)"
            ))

        has_amount_check = bool(re.search(r"\b(amount|price)\b.*(==|!=|>=|<=)|(==|!=|>=|<=).*\b(amount|price)\b", body, re.I))
        has_recipient_check = bool(re.search(r"\b(recipient|pay_to|payee)\b.*(==|!=)|(==|!=).*\b(recipient|pay_to|payee)\b", body, re.I))
        if not (has_amount_check and has_recipient_check):
            missing = []
            if not has_amount_check:
                missing.append("amount")
            if not has_recipient_check:
                missing.append("recipient")
            findings.append(Finding(
                id=new_id(), title=f"Payment handler `{f.name}` doesn't visibly check payment {' and '.join(missing)} against what was requested",
                severity="High", category="Payment Verification", line=f.start_line, function=f.name,
                description=f"`{f.name}` doesn't show a comparison confirming the paid {' or '.join(missing)} in the submitted proof matches what the service actually requested. A validly-signed payment for the wrong amount or to the wrong recipient could otherwise be accepted as satisfying the charge.",
                recommendation=f"Explicitly compare the {' and '.join(missing)} in the payment proof against the expected value for this specific request before granting access.",
                snippet=f"def {f.name}(...)"
            ))

        has_expiry_check = bool(re.search(r"expires_at|deadline|valid_until|expiry", body, re.I))
        if not has_expiry_check:
            findings.append(Finding(
                id=new_id(), title=f"Payment handler `{f.name}` has no visible expiry check",
                severity="Medium", category="Payment Verification", line=f.start_line, function=f.name,
                description=f"`{f.name}` shows no check of an expiry/deadline field on the payment proof. Without one, a very old (but validly-signed and otherwise unused) payment proof may remain acceptable indefinitely.",
                recommendation="Include and check an expiry timestamp on payment proofs, rejecting anything past its deadline even if otherwise valid and unused.",
                snippet=f"def {f.name}(...)"
            ))

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.line or 0))
    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("source", help="Path to .py agent code file")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    with open(args.source, "r", encoding="utf-8") as fh:
        src = fh.read()
    findings = analyze(src)
    result = {
        "file": args.source,
        "finding_count": len(findings),
        "by_severity": {sev: len([f for f in findings if f.severity == sev]) for sev in SEVERITY_ORDER},
        "findings": [asdict(f) for f in findings],
    }
    out_text = json.dumps(result, indent=2)
    if args.out:
        with open(args.out, "w") as f:
            f.write(out_text)
        print(f"Wrote {len(findings)} findings to {args.out}")
    else:
        print(out_text)


if __name__ == "__main__":
    main()
