#!/usr/bin/env python3
"""
Orditor Contract Analyzer
--------------------------
A lightweight static-analysis pass over Solidity source, modeled on the
checklist categories real audit firms (Trail of Bits / OpenZeppelin / Consensys
Diligence style reports) cover in a first pass: reentrancy, access control,
unchecked calls, dangerous opcodes, arithmetic, centralization, and code hygiene.

This is heuristic / regex + light scope-tracking analysis, NOT a full AST-based
tool (e.g. Slither). It is meant to catch known-pattern issues and organize them
into a formal, severity-rated finding set. It will produce false positives and
can miss issues a full symbolic/dataflow tool would catch — every finding
should be read as "worth a human look," not a proven vulnerability.

Usage:
    python3 analyzer.py <path-to-contract.sol> [--out findings.json]
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
    function: Optional[str]
    description: str
    recommendation: str
    snippet: str = ""


@dataclass
class Function:
    name: str
    start_line: int
    end_line: int
    signature: str
    modifiers: List[str] = field(default_factory=list)
    visibility: str = "public"


def strip_comments(src: str) -> str:
    src = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), src, flags=re.S)
    src = re.sub(r"//.*", "", src)
    return src


NON_MODIFIER_KEYWORDS = {
    "external", "public", "internal", "private", "view", "pure", "payable",
    "constant", "virtual", "override", "returns", "storage", "memory", "calldata", "immutable",
}


def parse_modifiers(tail: str) -> List[str]:
    """Generic modifier detection: anything in the function's post-params clause that
    isn't a visibility/mutability/returns keyword is treated as an applied modifier.
    This catches project-custom modifier names (e.g. `onlymanyowners`, `onlyRole`),
    not just a fixed whitelist."""
    t = re.sub(r"returns\s*\([^)]*\)", "", tail)
    mods = []
    for m in re.finditer(r"\b([A-Za-z_]\w*)\s*(\([^)]*\))?", t):
        name = m.group(1)
        if name and name not in NON_MODIFIER_KEYWORDS:
            mods.append(name)
    return mods


def extract_functions(lines: List[str]) -> List[Function]:
    """Very lightweight brace-depth scan to find function bodies and their modifiers."""
    functions = []
    fn_pattern = re.compile(
        r"function\s+(\w+)\s*\([^)]*\)\s*([^{;]*)"
    )
    depth = 0
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        m = fn_pattern.search(line)
        if m:
            # gather full signature across lines until we hit '{' or ';'
            sig_text = line
            j = i
            while "{" not in sig_text and ";" not in sig_text and j < n - 1:
                j += 1
                sig_text += " " + lines[j]
            name = m.group(1)
            m2 = fn_pattern.search(sig_text)
            tail = m2.group(2) if m2 else sig_text.split("{")[0]
            modifiers = parse_modifiers(tail)
            full_sig = sig_text.split("{")[0].strip()
            visibility = "public"
            for v in ("external", "internal", "private", "public"):
                if re.search(rf"\b{v}\b", tail):
                    visibility = v
                    break
            if "{" in sig_text:
                start = j
                depth = 0
                k = start
                seen_open = False
                while k < n:
                    depth += lines[k].count("{") - lines[k].count("}")
                    if "{" in lines[k]:
                        seen_open = True
                    if seen_open and depth <= 0:
                        break
                    k += 1
                end = min(k, n - 1)
                functions.append(Function(
                    name=name, start_line=i + 1, end_line=end + 1,
                    signature=full_sig, modifiers=modifiers, visibility=visibility
                ))
                i = end
        i += 1
    return functions


def function_for_line(functions: List[Function], line_no: int) -> Optional[Function]:
    for f in functions:
        if f.start_line <= line_no <= f.end_line:
            return f
    return None


SENSITIVE_NAME_RE = re.compile(
    r"\b(withdraw|mint|burn|setOwner|transferOwnership|kill|selfdestruct|pause|unpause|"
    r"upgrade|setFee|drain|rescue|sweep|emergencyWithdraw)\w*\b", re.I
)
# Names that are almost always privileged/admin actions regardless of who receives funds.
ADMIN_NAME_RE = re.compile(
    r"\b(mint|burn|setOwner|transferOwnership|kill|selfdestruct|pause|unpause|"
    r"upgrade|setFee|drain|rescue|sweep|emergencyWithdraw)\w*\b", re.I
)
SELF_TARGET_RE = re.compile(r"(payable\(\s*msg\.sender\s*\)|msg\.sender)\s*\.\s*(call|transfer|send)\b")


def analyze(source: str, filename: str = "contract.sol") -> List[Finding]:
    clean = strip_comments(source)
    lines = clean.splitlines()
    functions = extract_functions(lines)
    findings: List[Finding] = []
    fid = 0

    def new_id():
        nonlocal fid
        fid += 1
        return f"ORD-{fid:03d}"

    # 1. Pragma checks
    for i, line in enumerate(lines, 1):
        pragma_m = re.search(r"pragma\s+solidity\s+([^\s;]+)", line)
        if pragma_m:
            spec = pragma_m.group(1)
            if spec.startswith("^") or spec.startswith(">"):
                findings.append(Finding(
                    id=new_id(), title="Floating or unpinned compiler version",
                    severity="Low", category="Code Hygiene", line=i, function=None,
                    description=f'Pragma is "{spec}", allowing compilation with a range of compiler versions rather than a single audited one.',
                    recommendation="Pin to an exact compiler version (e.g. `pragma solidity 0.8.24;`) so the deployed bytecode matches what was reviewed.",
                    snippet=line.strip()
                ))
            ver_m = re.search(r"(\d+)\.(\d+)\.(\d+)", spec)
            if ver_m:
                major, minor = int(ver_m.group(1)), int(ver_m.group(2))
                if (major, minor) < (0, 8):
                    findings.append(Finding(
                        id=new_id(), title="Pre-0.8.x compiler: no built-in overflow/underflow checks",
                        severity="Medium", category="Arithmetic", line=i, function=None,
                        description="Solidity before 0.8.0 does not revert on integer overflow/underflow by default.",
                        recommendation="Upgrade to Solidity >=0.8.0, or confirm SafeMath (or an equivalent) is used on every arithmetic operation touching balances, supply, or accounting values.",
                        snippet=line.strip()
                    ))

    # 2. Reentrancy: external call followed by a state write in the same function,
    #    without a nonReentrant modifier.
    call_re = re.compile(r"\.(call)\s*(\{[^}]*\})?\s*\(|\.(send|transfer)\s*\(")
    state_write_re = re.compile(r"^\s*[\w.\[\]]+\s*(\+=|-=|=)(?!=)")
    for f in functions:
        if "nonReentrant" in f.modifiers:
            continue
        body_lines = lines[f.start_line - 1:f.end_line]
        call_line_idx = None
        for idx, l in enumerate(body_lines):
            if call_re.search(l):
                call_line_idx = idx
                break
        if call_line_idx is not None:
            for later in body_lines[call_line_idx + 1:]:
                if state_write_re.search(later) and "==" not in later:
                    abs_line = f.start_line + call_line_idx
                    findings.append(Finding(
                        id=new_id(), title=f"Possible reentrancy in `{f.name}`",
                        severity="High", category="Reentrancy", line=abs_line, function=f.name,
                        description="An external call (.call/.send/.transfer) appears before a state variable is updated in the same function, and no `nonReentrant` guard modifier was detected. If the callee is attacker-controlled, it may re-enter before state reflects the first call.",
                        recommendation="Apply checks-effects-interactions ordering (update state before the external call), and/or add a reentrancy guard (e.g. OpenZeppelin's `ReentrancyGuard`).",
                        snippet=body_lines[call_line_idx].strip()
                    ))
                    break

    # 3. tx.origin for authorization
    for i, line in enumerate(lines, 1):
        if re.search(r"tx\.origin", line):
            fn = function_for_line(functions, i)
            findings.append(Finding(
                id=new_id(), title="Use of tx.origin", severity="High", category="Access Control",
                line=i, function=fn.name if fn else None,
                description="`tx.origin` was found in the contract. If used for authorization, it is vulnerable to phishing via an intermediate malicious contract that forwards the call.",
                recommendation="Use `msg.sender` for authorization checks instead of `tx.origin`.",
                snippet=line.strip()
            ))

    # 4. Unchecked low-level call return value
    for i, line in enumerate(lines, 1):
        if re.search(r"\.call\s*(\{[^}]*\})?\s*\(", line) and "require(" not in line and "=" not in line.split(".call")[0][-15:]:
            fn = function_for_line(functions, i)
            findings.append(Finding(
                id=new_id(), title="Low-level `.call` return value may be unchecked",
                severity="Medium", category="Error Handling", line=i, function=fn.name if fn else None,
                description="A low-level `.call(...)` was found where the success flag doesn't appear to be captured/checked on this line. Unchecked calls can fail silently.",
                recommendation="Capture the return value: `(bool ok, ) = target.call(...); require(ok, \"call failed\");`",
                snippet=line.strip()
            ))

    # 5. Sensitive function without access control modifier or require(msg.sender==...)
    for f in functions:
        if SENSITIVE_NAME_RE.search(f.name):
            body = "\n".join(lines[f.start_line - 1:f.end_line])
            has_modifier_guard = bool(f.modifiers)
            has_inline_guard = bool(re.search(r"require\s*\(\s*msg\.sender\s*==", body)) or "onlyOwner" in body
            if has_modifier_guard or has_inline_guard:
                continue
            is_admin_named = bool(ADMIN_NAME_RE.search(f.name))
            if not is_admin_named:
                # "withdraw"-style name: only a real access-control gap if funds can go
                # somewhere other than msg.sender. Pure self-service withdrawal of the
                # caller's own balance isn't a privileged action.
                targets = re.findall(r"([\w.]+(?:\(\s*[\w.]*\s*\))?)\s*\.\s*(?:call|transfer|send)\b", body)
                has_send_call = bool(targets)
                pays_only_caller = has_send_call and all("msg.sender" in t for t in targets)
                if pays_only_caller:
                    continue
            if f.visibility in ("public", "external"):
                findings.append(Finding(
                    id=new_id(), title=f"Sensitive function `{f.name}` has no visible access control",
                    severity="Critical", category="Access Control", line=f.start_line, function=f.name,
                    description=f"`{f.name}` is {f.visibility} and its name suggests a privileged action (withdrawal, minting, ownership, pausing, or similar), but no access-control modifier or `require(msg.sender == ...)` guard was detected in its body or signature.",
                    recommendation="Restrict this function with an access-control modifier (e.g. `onlyOwner`, role-based access control) or an explicit `require` check, unless it is intentionally open to any caller.",
                    snippet=f.signature
                ))

    # 5b. Unprotected initializer / constructor-style function — this is the exact bug
    # class behind the 2017 Parity multisig freeze (initWallet had no access-control
    # guard and no re-init guard) and remains a live risk today in upgradeable/proxy
    # contracts whose `initialize()` isn't gated (OpenZeppelin's `initializer` modifier
    # exists specifically to close this).
    INIT_NAME_RE = re.compile(r"^(init|initialize|initWallet|setup|construct)\w*$", re.I)
    for f in functions:
        if not INIT_NAME_RE.match(f.name):
            continue
        if f.visibility not in ("public", "external"):
            continue
        body = "\n".join(lines[f.start_line - 1:f.end_line])
        has_modifier_guard = bool(f.modifiers)
        has_reinit_guard = bool(re.search(r"initiali[sz]ed", body, re.I)) or bool(
            re.search(r"require\s*\(\s*msg\.sender\s*==", body)
        )
        if has_modifier_guard or has_reinit_guard:
            continue
        findings.append(Finding(
            id=new_id(), title=f"Unprotected initializer `{f.name}`",
            severity="Critical", category="Access Control", line=f.start_line, function=f.name,
            description=f"`{f.name}` looks like an initializer/constructor-style function (sets up ownership, roles, or core state) but is {f.visibility} with no access-control modifier and no visible re-initialization guard (e.g. an `initialized` flag). If this is ever callable directly — including on a template/implementation contract behind a proxy, or a library deployed standalone — anyone can call it to seize privileged state. This is the exact bug class that caused the November 2017 Parity multisig freeze (~$280M locked): an unguarded `initWallet` let an attacker become the sole owner of the library contract, then legitimately call the contract's own owner-gated `kill` function.",
            recommendation="Add a one-time-use guard: either a boolean flag checked and set atomically (`require(!initialized); initialized = true;`), or (for upgradeable contracts) OpenZeppelin's `initializer` modifier from their Initializable pattern. Also confirm this function cannot be called directly on a deployed library/implementation contract outside its intended proxy/deployment context.",
            snippet=f.signature
        ))

    # 6. selfdestruct
    for i, line in enumerate(lines, 1):
        if re.search(r"\bselfdestruct\s*\(|\bsuicide\s*\(", line):
            fn = function_for_line(functions, i)
            guarded = fn and (fn.modifiers or "require(msg.sender ==" in "\n".join(lines[fn.start_line-1:fn.end_line]))
            findings.append(Finding(
                id=new_id(), title="Use of selfdestruct", severity="High" if not guarded else "Medium",
                category="Dangerous Operations", line=i, function=fn.name if fn else None,
                description="`selfdestruct` removes the contract's code and forcibly sends its balance to a target address. " + ("No access-control guard was detected on the enclosing function." if not guarded else "An access-control guard was detected, but review who can trigger it."),
                recommendation="Confirm this is intentional and tightly access-controlled. Note selfdestruct semantics have changed in recent EVM upgrades (EIP-6780) — confirm behavior on your target chain/fork.",
                snippet=line.strip()
            ))

    # 7. delegatecall
    for i, line in enumerate(lines, 1):
        if re.search(r"\.delegatecall\s*\(", line):
            fn = function_for_line(functions, i)
            findings.append(Finding(
                id=new_id(), title="Use of delegatecall", severity="High", category="Dangerous Operations",
                line=i, function=fn.name if fn else None,
                description="`delegatecall` executes external code in the calling contract's storage context. If the target address is user-suppliable or upgradable without safeguards, this can lead to full storage takeover.",
                recommendation="Confirm the delegatecall target is fixed, trusted, and storage-layout-compatible. If used for proxy patterns, use an audited proxy standard (e.g. OpenZeppelin's).",
                snippet=line.strip()
            ))

    # 8. block.timestamp / now for critical logic
    for i, line in enumerate(lines, 1):
        if re.search(r"\bblock\.timestamp\b|\bnow\b", line) and re.search(r"random|winner|lottery|seed", line, re.I):
            fn = function_for_line(functions, i)
            findings.append(Finding(
                id=new_id(), title="Timestamp used in apparent randomness/selection logic",
                severity="Medium", category="Predictability", line=i, function=fn.name if fn else None,
                description="`block.timestamp` (or `now`) appears near randomness/selection-related logic. Miners/validators have some influence over the timestamp, making it unsuitable as a sole entropy source.",
                recommendation="Use a verifiable randomness source (e.g. Chainlink VRF) rather than block-derived values for anything of value.",
                snippet=line.strip()
            ))

    # 9. Missing events on state changes in sensitive functions (traces one level into
    #    internal helper calls, since e.g. transferOwnership() often just calls
    #    _transferOwnership() which is where the actual `emit` lives)
    emits_directly = {}
    for f in functions:
        body = "\n".join(lines[f.start_line - 1:f.end_line])
        emits_directly[f.name] = bool(re.search(r"\bemit\s+\w+", body))

    for f in functions:
        if SENSITIVE_NAME_RE.search(f.name):
            body = "\n".join(lines[f.start_line - 1:f.end_line])
            if emits_directly.get(f.name):
                continue
            called_names = set(re.findall(r"\b(_?\w+)\s*\(", body)) - {f.name}
            emits_indirectly = any(emits_directly.get(n) for n in called_names if n in emits_directly)
            if emits_indirectly:
                continue
            findings.append(Finding(
                id=new_id(), title=f"No event emitted in `{f.name}`",
                severity="Low", category="Observability", line=f.start_line, function=f.name,
                description=f"`{f.name}` appears to change state (based on its name) but no `emit` statement was found in its body or in an internal helper it calls.",
                recommendation="Emit an event on state-changing actions so off-chain systems and users can monitor activity.",
                snippet=f.signature
            ))

    # 10. Unbounded loop over storage/dynamic array
    for i, line in enumerate(lines, 1):
        if re.search(r"for\s*\(\s*[\w\s]+=\s*0\s*;\s*\w+\s*<\s*\w+\.length", line):
            fn = function_for_line(functions, i)
            findings.append(Finding(
                id=new_id(), title="Loop bound to a dynamic array's length",
                severity="Medium", category="Denial of Service", line=i, function=fn.name if fn else None,
                description="A loop iterates up to `<array>.length`. If that array can grow without bound (e.g. via user-triggered pushes), the function can eventually exceed the block gas limit and become uncallable.",
                recommendation="Cap iteration, paginate the operation, or use a pull-based pattern instead of iterating an unbounded array in one transaction.",
                snippet=line.strip()
            ))

    # 11. assert() used for input validation
    for i, line in enumerate(lines, 1):
        if re.search(r"\bassert\s*\(", line):
            fn = function_for_line(functions, i)
            findings.append(Finding(
                id=new_id(), title="assert() used where require() may be intended",
                severity="Informational", category="Code Hygiene", line=i, function=fn.name if fn else None,
                description="`assert()` consumes all remaining gas on failure (pre-0.8.0) and signals an internal invariant violation, not a user input error.",
                recommendation="Use `require()` for input validation and external condition checks; reserve `assert()` for invariants that should never be false.",
                snippet=line.strip()
            ))

    # 12. Centralization: single owner with broad powers (heuristic summary, not per-line)
    owner_powers = [f for f in functions if f.modifiers and SENSITIVE_NAME_RE.search(f.name)]
    if len(owner_powers) >= 2:
        names = ", ".join(sorted({f"`{f.name}`" for f in owner_powers}))
        findings.append(Finding(
            id=new_id(), title="Centralization risk: privileged role controls multiple sensitive functions",
            severity="Medium", category="Centralization", line=None, function=None,
            description=f"Multiple sensitive functions ({names}) are gated behind what appears to be a single privileged role. If that key/role is compromised or misused, it can affect funds, supply, or contract state broadly.",
            recommendation="Consider a multisig or timelock for privileged actions, and document the trust assumptions clearly for users.",
            snippet=""
        ))

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.line or 0))
    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("contract", help="Path to .sol file")
    ap.add_argument("--out", default=None, help="Write findings JSON here")
    args = ap.parse_args()

    with open(args.contract, "r", encoding="utf-8") as fh:
        src = fh.read()

    findings = analyze(src, filename=args.contract)
    result = {
        "file": args.contract,
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
        print(f"Wrote {len(findings)} findings to {args.out}")
    else:
        print(out_text)


if __name__ == "__main__":
    main()
