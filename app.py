#!/usr/bin/env python3
"""
Orditor AIX — Vercel-deployable web app.

Same four engines as the local version, restructured for serverless:
  - entrypoint is `app` (Flask instance) at the project root, per Vercel's
    Python runtime auto-detection
  - docx generation is pure Python (report_generator.py / python-docx),
    no Node subprocess — a serverless function can't reliably shell out
  - the download link is a base64 data: URI embedded directly in the results
    page, generated in the same request as the audit — Vercel functions are
    stateless and ephemeral between invocations, so a separate "GET
    /download/<id>" endpoint relying on an in-memory dict or a file left on
    disk from a prior request would not work reliably here.

Runs locally the same way as before: python3 app.py -> http://localhost:5000
Deploys to Vercel by pushing this project (with requirements.txt) to a repo
and importing it, or running `vercel` in this folder.
"""

import os
import sys
import json
import base64
from dataclasses import asdict
from flask import Flask, request, render_template_string

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from engines import contract_engine, api_engine, agent_engine, boundary_engine
from report_generator import report_bytes

app = Flask(__name__)

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}

SURFACE_BY_ENGINE_CATEGORY = {
    ("contract", "Reentrancy"): "Blockchain", ("contract", "Access Control"): "Blockchain",
    ("contract", "Dangerous Operations"): "Blockchain", ("contract", "Arithmetic"): "Blockchain",
    ("contract", "Error Handling"): "Blockchain", ("contract", "Denial of Service"): "Blockchain",
    ("contract", "Predictability"): "Blockchain", ("contract", "Centralization"): "Blockchain",
    ("contract", "Code Hygiene"): "Blockchain", ("contract", "Observability"): "Blockchain",
    ("api", "Configuration"): "Application", ("api", "Secrets Management"): "Application",
    ("api", "CORS"): "Application", ("api", "Access Control"): "Application",
    ("api", "Injection"): "Application", ("api", "Error Handling"): "Application",
    ("api", "Data Handling"): "Application", ("api", "Denial of Service"): "Application",
    ("api", "Transport Security"): "Application",
    ("agent", "Containment"): "Agent", ("agent", "Payment Verification"): "Agent",
    ("boundary", "AI-Blockchain Boundary"): "Integration",
}
IMPACT_BY_CATEGORY = {
    "Reentrancy": "Funds", "Dangerous Operations": "Funds", "AI-Blockchain Boundary": "Funds",
    "Payment Verification": "Funds", "Arithmetic": "Integrity", "Centralization": "Integrity",
    "Denial of Service": "Availability", "Predictability": "Integrity", "Secrets Management": "Privacy",
    "Data Handling": "Privacy", "Containment": "Privilege", "Access Control": "Privilege",
    "Injection": "Integrity", "CORS": "Privacy", "Configuration": "Privilege",
    "Error Handling": "Privacy", "Transport Security": "Privacy", "Code Hygiene": "Reputation",
    "Observability": "Reputation",
}
CONFIRMED_CATEGORIES = {"Secrets Management", "Configuration"}
MAX_FILE_BYTES = 300_000  # keep each analyzed file well under Vercel's execution budget


def classify(engine_name, finding):
    category = finding.get("category", "")
    finding["surface"] = SURFACE_BY_ENGINE_CATEGORY.get((engine_name, category), "Application")
    finding["impact"] = IMPACT_BY_CATEGORY.get(category, "Integrity")
    finding["confidence"] = "Confirmed" if category in CONFIRMED_CATEGORIES else "Probable"
    finding["engine"] = engine_name
    return finding


def run_on_source(filename, src):
    findings = []
    if filename.endswith(".sol"):
        try:
            for f in contract_engine.analyze(src, filename=filename):
                d = asdict(f); d["file"] = filename
                findings.append(classify("contract", d))
        except Exception:
            pass
    elif filename.endswith(".py"):
        try:
            api_findings, _routes = api_engine.analyze(src, filename=filename)
            for f in api_findings:
                d = asdict(f); d["file"] = filename
                findings.append(classify("api", d))
        except Exception:
            pass
        try:
            for f in agent_engine.analyze(src):
                d = asdict(f); d["file"] = filename
                findings.append(classify("agent", d))
        except Exception:
            pass
        try:
            for f in boundary_engine.analyze(src):
                d = asdict(f); d["file"] = filename
                findings.append(classify("boundary", d))
        except Exception:
            pass
    return findings


def build_attack_chain_notes(findings):
    notable = [f for f in findings if f["severity"] in ("Critical", "High")]
    by_surface = {}
    for f in notable:
        by_surface.setdefault(f["surface"], []).append(f)
    if len(by_surface) < 2:
        return []
    notes = []
    if "Agent" in by_surface and "Integration" in by_surface:
        notes.append(
            f"Agent containment gap + unvalidated AI\u2192blockchain boundary: "
            f"\u201c{by_surface['Agent'][0]['title']}\u201d combined with \u201c{by_surface['Integration'][0]['title']}\u201d "
            "means an agent that can be steered off-task has a direct, unchecked path to moving funds."
        )
    if "Application" in by_surface and "Blockchain" in by_surface:
        notes.append(
            f"Application-layer gap + contract-layer gap: "
            f"\u201c{by_surface['Application'][0]['title']}\u201d sitting in front of "
            f"\u201c{by_surface['Blockchain'][0]['title']}\u201d may mean the application bug is the actual "
            "entry point that reaches the contract issue."
        )
    if not notes:
        notes.append(f"Critical/High findings span multiple surfaces ({', '.join(sorted(by_surface))}) \u2014 review whether they compose into one path.")
    return notes


def run_audit(files: dict, project_name: str):
    """files: {filename: source_text}"""
    all_findings = []
    for filename, src in files.items():
        all_findings.extend(run_on_source(filename, src))
    all_findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f.get("file", ""), f.get("line") or 0))

    by_severity = {sev: len([f for f in all_findings if f["severity"] == sev]) for sev in SEVERITY_ORDER}
    by_surface = {}
    for f in all_findings:
        by_surface[f["surface"]] = by_surface.get(f["surface"], 0) + 1

    return {
        "project_name": project_name,
        "targets_scanned": list(files.keys()),
        "finding_count": len(all_findings),
        "by_severity": by_severity,
        "by_surface": by_surface,
        "attack_chain_notes": build_attack_chain_notes(all_findings),
        "findings": all_findings,
    }


PAGE_STYLE = """
<style>
  :root { --bg:#0c0e0d; --panel:#14161a; --panel2:#1a1d22; --line:#2a2e35; --ink:#e9ebe6; --dim:#9a9fa6;
          --violet:#8b7cf6; --pass:#3fbf7f; --caution:#e0a83e; --fail:#e5555f; }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--ink);font-family:'IBM Plex Mono',monospace;line-height:1.5;padding:0 0 60px;}
  .wrap{max-width:920px;margin:0 auto;padding:32px 20px;}
  header{border-bottom:1px solid var(--line);padding-bottom:18px;margin-bottom:26px;}
  h1{font-size:26px;margin:0 0 4px;} .sub{color:var(--dim);font-size:13px;}
  .violet{color:var(--violet);}
  .panel{background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:22px;margin-bottom:20px;}
  label{display:block;font-size:12px;color:var(--dim);margin:12px 0 6px;}
  input[type=text],textarea{width:100%;background:var(--panel2);border:1px solid var(--line);color:var(--ink);
    padding:9px 10px;border-radius:4px;font-family:inherit;font-size:13px;}
  textarea{min-height:220px;resize:vertical;}
  input[type=file]{color:var(--dim);font-size:12px;}
  button{background:var(--violet);color:#0c0e0d;border:none;padding:12px 20px;font-weight:600;
    border-radius:4px;cursor:pointer;font-family:inherit;font-size:13px;text-transform:uppercase;letter-spacing:.03em;}
  button:hover{opacity:.9;}
  .filerow{border:1px dashed var(--line);border-radius:4px;padding:16px;margin-bottom:10px;}
  .stamp{display:inline-block;font-size:22px;font-weight:700;padding:8px 18px;border:3px solid;border-radius:4px;transform:rotate(-2deg);}
  .stamp.Critical,.stamp.High{color:var(--fail);border-color:var(--fail);}
  .stamp.Medium,.stamp.Low{color:var(--caution);border-color:var(--caution);}
  .stamp.None{color:var(--pass);border-color:var(--pass);}
  table{width:100%;border-collapse:collapse;margin:14px 0;font-size:12.5px;}
  td,th{border:1px solid var(--line);padding:7px 10px;text-align:left;}
  th{background:#1e2126;}
  .flag{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--line);border-radius:4px;
    padding:14px 16px;margin-bottom:10px;}
  .flag.Critical,.flag.High{border-left-color:var(--fail);}
  .flag.Medium,.flag.Low{border-left-color:var(--caution);}
  .sev{font-size:9.5px;letter-spacing:.08em;text-transform:uppercase;padding:2px 7px;border-radius:3px;font-weight:700;margin-right:8px;}
  .sev.Critical,.sev.High{background:rgba(229,85,95,.15);color:var(--fail);}
  .sev.Medium,.sev.Low{background:rgba(224,168,62,.15);color:var(--caution);}
  .meta{color:var(--dim);font-size:11px;margin:4px 0 8px;}
  .desc{font-size:12.5px;margin:6px 0;} .rec{font-size:12.5px;color:var(--dim);}
  code{background:var(--panel2);padding:1px 5px;border-radius:3px;}
  .chain{background:rgba(229,85,95,.08);border:1px solid var(--fail);border-radius:4px;padding:12px 14px;margin-bottom:10px;font-size:12.5px;}
  a.dl{display:inline-block;margin-top:10px;color:var(--violet);text-decoration:none;font-size:13px;}
  a.dl:hover{text-decoration:underline;}
</style>
"""

UPLOAD_PAGE = """
<!doctype html><html><head><meta charset="utf-8"><title>Orditor AIX</title>""" + PAGE_STYLE + """</head><body>
<div class="wrap">
  <header>
    <h1><span class="violet">ORDITOR</span> AIX</h1>
    <div class="sub">AI / Web3 Security Audit Framework &mdash; upload or paste code, run the audit, get a report.</div>
  </header>

  <form method="post" action="/audit" enctype="multipart/form-data">
    <div class="panel">
      <label for="project_name">Project name</label>
      <input type="text" name="project_name" id="project_name" placeholder="e.g. My Agent Backend">

      <label>Upload files (.py / .sol) &mdash; select multiple</label>
      <div class="filerow"><input type="file" name="files" multiple accept=".py,.sol"></div>

      <label for="paste_code">...or paste a single file's code here</label>
      <textarea name="paste_code" id="paste_code" placeholder="Paste Python or Solidity source..."></textarea>
      <label for="paste_filename">Filename for pasted code (needed to route to the right engine)</label>
      <input type="text" name="paste_filename" id="paste_filename" placeholder="e.g. agent_backend.py or contract.sol">
    </div>
    <button type="submit">Run Audit</button>
  </form>
</div>
</body></html>
"""


def render_results(result, docx_b64):
    counts = result["by_severity"]
    if counts.get("Critical"): stamp_class, stamp_label = "Critical", "CRITICAL RISK"
    elif counts.get("High"): stamp_class, stamp_label = "High", "HIGH RISK"
    elif counts.get("Medium"): stamp_class, stamp_label = "Medium", "MEDIUM RISK"
    elif counts.get("Low"): stamp_class, stamp_label = "Low", "LOW RISK"
    else: stamp_class, stamp_label = "None", "NO FINDINGS"

    sev_rows = "".join(f"<tr><td>{s}</td><td>{counts.get(s,0)}</td></tr>" for s in SEVERITY_ORDER)
    surf_rows = "".join(f"<tr><td>{s}</td><td>{n}</td></tr>" for s, n in result["by_surface"].items())
    chain_html = "".join(f'<div class="chain">{note}</div>' for note in result["attack_chain_notes"]) or '<div class="meta">No cross-surface Critical/High combination detected.</div>'

    flags_html = ""
    for f in result["findings"]:
        loc = f"Line {f['line']}" if f.get("line") else "File-wide"
        fn = f" &mdash; <code>{f['function']}</code>" if f.get("function") else ""
        snippet = f'<div class="meta"><code>{f["snippet"]}</code></div>' if f.get("snippet") else ""
        flags_html += f"""
        <div class="flag {f['severity']}">
          <span class="sev {f['severity']}">{f['severity']}</span><b>{f['title']}</b>
          <div class="meta">{f['id']} &middot; {f['surface']} &middot; {f['confidence']} confidence &middot; impact: {f['impact']} &middot; {f['file']} &middot; {loc}{fn}</div>
          <div class="desc">{f['description']}</div>
          {snippet}
          <div class="rec"><b>Recommendation:</b> {f['recommendation']}</div>
        </div>
        """

    download_html = ""
    if docx_b64:
        download_html = (
            f'<a class="dl" download="orditor_aix_report.docx" '
            f'href="data:application/vnd.openxmlformats-officedocument.wordprocessingml.document;base64,{docx_b64}">'
            f'&#8595; Download formal report (.docx)</a>'
        )

    return f"""
    <!doctype html><html><head><meta charset="utf-8"><title>Orditor AIX \u2014 Results</title>{PAGE_STYLE}</head><body>
    <div class="wrap">
      <header>
        <h1><span class="violet">ORDITOR</span> AIX \u2014 Results</h1>
        <div class="sub">{result['project_name']} &middot; {len(result['targets_scanned'])} file(s) scanned &middot; {result['finding_count']} finding(s)</div>
      </header>

      <div class="panel">
        <span class="stamp {stamp_class}">{stamp_label}</span>
        <table><tr><th>Severity</th><th>Count</th></tr>{sev_rows}</table>
        <table><tr><th>Surface</th><th>Findings</th></tr>{surf_rows}</table>
        {download_html}
      </div>

      <div class="panel">
        <b>Attack Chain Analysis</b>
        {chain_html}
      </div>

      <div class="panel">
        <b>Findings</b>
        {flags_html}
      </div>

      <a class="dl" href="/">&larr; Run another audit</a>
    </div>
    </body></html>
    """


@app.route("/")
def index():
    return UPLOAD_PAGE


@app.route("/audit", methods=["POST"])
def audit():
    project_name = request.form.get("project_name") or "Untitled Project"
    files = {}

    for f in request.files.getlist("files"):
        if f and f.filename and (f.filename.endswith(".py") or f.filename.endswith(".sol")):
            content = f.read(MAX_FILE_BYTES + 1)
            if len(content) > MAX_FILE_BYTES:
                continue  # skip oversized files rather than risk the function timeout
            try:
                files[os.path.basename(f.filename)] = content.decode("utf-8")
            except UnicodeDecodeError:
                continue

    paste_code = request.form.get("paste_code", "").strip()
    paste_filename = request.form.get("paste_filename", "").strip()
    if paste_code and paste_filename and (paste_filename.endswith(".py") or paste_filename.endswith(".sol")):
        files[os.path.basename(paste_filename)] = paste_code[:MAX_FILE_BYTES]

    if not files:
        return "<p>No valid .py or .sol files provided. <a href='/'>Go back</a>.</p>", 400

    result = run_audit(files, project_name)

    meta = {
        "projectName": project_name,
        "auditDate": "generated by Orditor AIX web app",
        "reportVersion": "1.0",
        "scopeNote": "Files uploaded/pasted via the Orditor AIX web app.",
    }
    report_data = {
        "targets_scanned": result["targets_scanned"],
        "finding_count": result["finding_count"],
        "by_severity": result["by_severity"],
        "by_surface": result["by_surface"],
        "attack_chain_notes": result["attack_chain_notes"],
        "findings": result["findings"],
    }
    try:
        docx_bytes = report_bytes(report_data, meta)
        docx_b64 = base64.b64encode(docx_bytes).decode("ascii")
    except Exception:
        docx_b64 = None

    return render_results(result, docx_b64)


if __name__ == "__main__":
    print("Orditor AIX running at http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
