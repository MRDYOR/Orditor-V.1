#!/usr/bin/env python3
"""
Orditor AI<->Blockchain Boundary Analyzer  (Phase 4 of the AIX framework)
---------------------------------------------------------------------------
This is the check that doesn't exist as a standalone concern in either the
contract analyzer or the API/agent analyzers individually — it lives at the
seam between them.

The question, straight from the framework:

    If AI generates:
        recipient = X
        amount = Y
        contract = Z
        function = withdraw()
    there should be independent deterministic validation.

Concretely: does a value that plausibly came from a model's decision
(a dict key like "recipient"/"to"/"amount"/"token_out", a variable named
after an LLM response) flow into transaction-construction/signing code
(web3.py's build_transaction / send_transaction / sign_transaction, or a
contract .functions.X().transact() call) without a deterministic check
(an allowlist, a bound/limit comparison, a require-style validation) sitting
between the two?

Same caveat as the other three engines: heuristic pattern matching over
source text, not real dataflow/taint tracking. It follows "does a
validation-shaped call appear anywhere between the AI-decision line and the
transaction line, in the same function" — it does not prove the validation
is correct, only that something resembling one exists.

Usage:
    python3 boundary_engine.py <path-to-agent_backend.py> [--out findings.json]
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


def strip_comments(source: str) -> str:
    lines = source.splitlines()
    out = []
    in_triple = False
    for line in lines:
        if '"""' in line or "'''" in line:
            count = line.count('"""') + line.count("'''")
            if count % 2 == 1:
                in_triple = not in_triple
            out.append("")
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


# Signals that a value plausibly originated from a model's decision rather
# than a fixed/config value.
AI_DECISION_SOURCE_RE = re.compile(
    r"\b(llm_decision|model_decision|agent_decision|decision|llm_response|"
    r"model_response|agent_output|llm_output|parsed_response|ai_decision|"
    r"trading_decision|response\.get|decision\.get|decision\[)", re.I
)
AI_DECISION_KEY_RE = re.compile(
    r"\[\s*[\"'](recipient|to|amount|token_out|token_in|contract|function|"
    r"action|target|destination|pay_to)[\"']\s*\]|"
    r"\.get\(\s*[\"'](recipient|to|amount|token_out|token_in|contract|function|"
    r"action|target|destination|pay_to)[\"']", re.I
)

TX_CONSTRUCT_RE = re.compile(
    r"build_transaction|buildTransaction|send_transaction|sendTransaction|"
    r"sign_transaction|signTransaction|\.functions\.\w+\([^)]*\)\.transact|"
    r"\.functions\.\w+\([^)]*\)\.build_transaction", re.I
)

VALIDATION_HINT_RE = re.compile(
    r"allowlist|allowed_(tokens|addresses|contracts|recipients)|ALLOWED_|"
    r"whitelist|max_(amount|trade|spend)|MAX_(AMOUNT|TRADE|SPEND)|"
    r"require\(|assert\s|validate_|is_valid|sanity_check|bounds_check|"
    r"within_limit|simulate_|dry_run|deterministic", re.I
)


def analyze(source: str) -> List[Finding]:
    lines = source.splitlines()
    code_only = strip_comments(source)
    code_lines = code_only.splitlines()
    funcs = extract_functions(lines)
    findings: List[Finding] = []
    fid = 0

    def new_id():
        nonlocal fid
        fid += 1
        return f"ORD-BND-{fid:03d}"

    for f in funcs:
        body_lines = code_lines[f.start_line - 1:f.end_line]
        body = "\n".join(body_lines)

        has_ai_decision = bool(AI_DECISION_SOURCE_RE.search(body)) or bool(AI_DECISION_KEY_RE.search(body))
        has_tx_construct = bool(TX_CONSTRUCT_RE.search(body))
        if not (has_ai_decision and has_tx_construct):
            continue

        # find the first AI-decision-shaped line and first tx-construct line,
        # then check whether a validation-shaped call sits between them
        decision_line_idx = None
        tx_line_idx = None
        for idx, l in enumerate(body_lines):
            if decision_line_idx is None and (AI_DECISION_SOURCE_RE.search(l) or AI_DECISION_KEY_RE.search(l)):
                decision_line_idx = idx
            if TX_CONSTRUCT_RE.search(l):
                tx_line_idx = idx
                break  # first tx-construct after decision is what matters
        if decision_line_idx is None or tx_line_idx is None or tx_line_idx < decision_line_idx:
            # can't establish clear ordering; still worth flagging at Medium
            findings.append(Finding(
                id=new_id(), title=f"`{f.name}` mixes AI-decision data and transaction construction — ordering unclear",
                severity="Medium", category="AI-Blockchain Boundary", line=f.start_line, function=f.name,
                description=f"`{f.name}` contains both AI/model-decision-shaped data and transaction-construction/signing calls, but a clear before/after ordering between them couldn't be established from source alone. Worth a manual read to confirm whether the AI's output is validated before being used to build a transaction.",
                recommendation="Confirm explicitly: does independent, deterministic code validate the AI-chosen recipient/amount/contract/function against fixed bounds before any transaction is built?",
                snippet=f"def {f.name}(...)"
            ))
            continue

        between = "\n".join(body_lines[decision_line_idx:tx_line_idx + 1])
        has_validation = bool(VALIDATION_HINT_RE.search(between))

        if not has_validation:
            findings.append(Finding(
                id=new_id(),
                title=f"AI-decided value flows into a transaction in `{f.name}` with no independent validation",
                severity="Critical", category="AI-Blockchain Boundary",
                line=f.start_line + decision_line_idx, function=f.name,
                description=(
                    f"`{f.name}` takes a value that appears to come from a model/agent decision "
                    f"(line {f.start_line + decision_line_idx}) and uses it to construct/sign a blockchain "
                    f"transaction (line {f.start_line + tx_line_idx}), with no allowlist check, bound/limit "
                    f"comparison, `require`-style validation, or simulation/dry-run detected in between. "
                    f"This is exactly the gap the framework's Phase 4 targets: recipient, amount, contract, "
                    f"or function chosen by the model is trusted as-is rather than checked deterministically "
                    f"before funds move."
                ),
                recommendation=(
                    "Add independent, deterministic validation between the AI's decision and transaction "
                    "construction: an allowlist for destination addresses/contracts, a hard ceiling on amount, "
                    "and ideally a simulation/dry-run step — none of which should themselves depend on the "
                    "model's output being trustworthy."
                ),
                snippet=body_lines[decision_line_idx].strip()
            ))
        else:
            findings.append(Finding(
                id=new_id(),
                title=f"AI-decided value flows into a transaction in `{f.name}` — validation present, confirm it's sufficient",
                severity="Low", category="AI-Blockchain Boundary",
                line=f.start_line + decision_line_idx, function=f.name,
                description=f"`{f.name}` shows a validation-shaped check between the AI decision and the transaction call. Flagged at low severity as a reminder to manually confirm the check actually covers recipient, amount, and any other AI-chosen parameter — not just one of them.",
                recommendation="Manually confirm the validation covers every AI-influenced transaction parameter (recipient, amount, token/contract, function selector), not just the first one checked.",
                snippet=body_lines[decision_line_idx].strip()
            ))

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.line or 0))
    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("source")
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
