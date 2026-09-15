from fastapi import FastAPI, Form, UploadFile, File
from fastapi.responses import HTMLResponse, StreamingResponse, PlainTextResponse
from scanner import scan_site_async, scan_many
from io import BytesIO
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
import csv
import re

app = FastAPI(title="WP Prospect Scanner")


def esc(value):
    if value is None:
        return ""
    s = str(value)
    return (
        s.replace("&", "&amp;")
         .replace("<", "&lt;")
         .replace(">", "&gt;")
         .replace('"', "&quot;")
    )


def findings_rows(findings):
    rows = []
    for item in findings or []:
        if isinstance(item, (list, tuple)) and len(item) >= 2:
            severity = item[0]
            message = item[1]
        elif isinstance(item, dict):
            severity = item.get("severity", item.get("level", "Info"))
            message = item.get("message", item.get("finding", ""))
        else:
            severity = "Info"
            message = str(item)
        rows.append((str(severity), str(message)))
    return rows


def render_report(result):
    findings = findings_rows(result.get("findings", []))
    rows_html = ""
    for severity, message in findings:
        rows_html += (
            "<tr>"
            f"<td><b>{esc(severity)}</b></td>"
            f"<td>{esc(message)}</td>"
            "</tr>"
        )

    if not rows_html:
        rows_html = "<tr><td>Info</td><td>No actionable findings detected.</td></tr>"

    return f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WP Prospect Scanner</title>
<style>
body{{font-family:Arial,sans-serif;max-width:1000px;margin:30px auto;padding:0 16px;color:#222}}
h1{{margin-bottom:6px}}
.card{{border:1px solid #ddd;border-radius:10px;padding:18px;margin:16px 0}}
.score{{font-size:30px;font-weight:bold}}
table{{width:100%;border-collapse:collapse}}
th,td{{padding:10px;border:1px solid #ddd;text-align:left;vertical-align:top}}
th{{background:#f5f5f5}}
input[type=url],input[type=file]{{padding:10px;width:100%;box-sizing:border-box}}
button{{padding:10px 16px;margin-top:8px;cursor:pointer}}
.small{{color:#666;font-size:14px}}
.error{{color:#b00020;font-weight:bold}}
</style>
</head>
<body>
<h1>WP Prospect Scanner</h1>
<div class="card">
<div class="small">URL</div>
<div><a href="{esc(result.get("url",""))}" target="_blank" rel="noopener">{esc(result.get("url",""))}</a></div>
<p><b>Final URL:</b> {esc(result.get("final_url",""))}</p>
<p><b>HTTP status:</b> {esc(result.get("status_code",""))}</p>
<p><b>WordPress:</b> {"Yes" if result.get("wordpress") else "No / not confirmed"}</p>
<p><b>WordPress version:</b> {esc(result.get("wp_version") or "Not detected")}</p>
<p class="score">Lead score: {esc(result.get("lead_score",0))}</p>
</div>

<div class="card">
<h2>Findings</h2>
<table>
<thead><tr><th>Severity</th><th>Finding</th></tr></thead>
<tbody>{rows_html}</tbody>
</table>
</div>

<div class="card">
<h2>Page information</h2>
<p><b>Title:</b> {esc(result.get("title",""))}</p>
<p><b>Description:</b> {esc(result.get("description",""))}</p>
<p><b>Canonical:</b> {esc(result.get("canonical",""))}</p>
<p><b>H1 count:</b> {esc(result.get("h1_count",""))}</p>
<p><b>Images:</b> {esc(result.get("image_count",""))}</p>
<p><b>Images missing ALT:</b> {esc(result.get("missing_alt_count",""))}</p>
<p><b>Missing security headers:</b> {esc(", ".join(result.get("missing_security_headers",[]) or []) or "None")}</p>
</div>

<div class="card">
<h2>Browser checks</h2>
<p><b>JavaScript errors:</b> {esc(len(result.get("js_errors",[]) or []))}</p>
<p><b>Console errors:</b> {esc(len(result.get("console_errors",[]) or []))}</p>
<p><b>Failed resources:</b> {esc(len(result.get("failed_requests",[]) or []))}</p>
<p><b>Desktop horizontal overflow:</b> {esc(result.get("desktop_horizontal_overflow","Not tested"))}</p>
<p><b>Mobile horizontal overflow:</b> {esc(result.get("mobile_horizontal_overflow","Not tested"))}</p>
<p><b>DOMContentLoaded:</b> {esc(result.get("dom_content_loaded_ms",""))} ms</p>
</div>

<div class="card">
<h2>WordPress indicators</h2>
<p>{esc(", ".join(result.get("wp_indicators",[]) or []) or "None")}</p>
</div>

<div class="card">
<h2>Special endpoints</h2>
<pre>{esc(result.get("special_endpoints",{}))}</pre>
</div>

<div class="card">
<a href="/report-html?url={esc(result.get("url",""))}">Refresh report</a>
</div>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
async def home():
    return """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WP Prospect Scanner</title>
<style>
body{font-family:Arial,sans-serif;max-width:850px;margin:30px auto;padding:0 16px}
.card{border:1px solid #ddd;border-radius:10px;padding:20px;margin:20px 0}
input[type=url],input[type=file]{width:100%;box-sizing:border-box;padding:12px;margin:8px 0}
button{padding:11px 18px;cursor:pointer}
.small{color:#666}
</style>
</head>
<body>
<h1>WP Prospect Scanner</h1>
<p class="small">Passive WordPress prospecting and website audit.</p>

<div class="card">
<h2>Quick scan</h2>
<form method="post" action="/scan">
<input type="url" name="url" placeholder="https://example.com" required>
<button type="submit">Scan website</button>
</form>
</div>

<div class="card">
<h2>Batch scan</h2>
<form method="post" action="/batch" enctype="multipart/form-data">
<input type="file" name="file" accept=".txt,.csv" required>
<button type="submit">Scan list</button>
</form>
<p class="small">One URL per line, or a CSV containing URLs. Maximum 50 URLs.</p>
</div>
</body>
</html>"""


@app.post("/scan", response_class=HTMLResponse)
async def scan(url: str = Form(...)):
    result = await scan_site_async(url)
    return HTMLResponse(render_report(result))


@app.get("/report-html", response_class=HTMLResponse)
async def report_html(url: str):
    result = await scan_site_async(url)
    return HTMLResponse(render_report(result))


@app.post("/report")
async def report(url: str = Form(...)):
    result = await scan_site_async(url)

    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, rightMargin=36, leftMargin=36,
                            topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("WordPress Prospect Scanner Report", styles["Title"]))
    story.append(Spacer(1, 10))
    story.append(Paragraph(f"URL: {esc(result.get('url',''))}", styles["BodyText"]))
    story.append(Paragraph(f"Final URL: {esc(result.get('final_url',''))}", styles["BodyText"]))
    story.append(Paragraph(f"HTTP status: {esc(result.get('status_code',''))}", styles["BodyText"]))
    story.append(Paragraph(
        f"WordPress: {'Yes' if result.get('wordpress') else 'No / not confirmed'}",
        styles["BodyText"]
    ))
    story.append(Paragraph(
        f"WordPress version: {esc(result.get('wp_version') or 'Not detected')}",
        styles["BodyText"]
    ))
    story.append(Paragraph(
        f"Lead score: {esc(result.get('lead_score',0))}",
        styles["Heading2"]
    ))
    story.append(Spacer(1, 10))

    data = [["Severity", "Finding"]]
    for severity, message in findings_rows(result.get("findings", [])):
        data.append([severity, message])
    if len(data) == 1:
        data.append(["Info", "No actionable findings detected."])

    table = Table(data, colWidths=[80, 420])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.lightgrey),
        ("GRID", (0,0), (-1,-1), 0.5, colors.grey),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
        ("LEFTPADDING", (0,0), (-1,-1), 6),
        ("RIGHTPADDING", (0,0), (-1,-1), 6),
        ("TOPPADDING", (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
    ]))
    story.append(table)
    story.append(Spacer(1, 14))

    info = [
        ["Title", str(result.get("title",""))],
        ["Description", str(result.get("description",""))],
        ["Canonical", str(result.get("canonical",""))],
        ["H1 count", str(result.get("h1_count",""))],
        ["Images", str(result.get("image_count",""))],
        ["Missing ALT", str(result.get("missing_alt_count",""))],
        ["Missing security headers", ", ".join(result.get("missing_security_headers",[]) or [])],
        ["JS errors", str(len(result.get("js_errors",[]) or []))],
        ["Console errors", str(len(result.get("console_errors",[]) or []))],
        ["Failed resources", str(len(result.get("failed_requests",[]) or []))],
    ]
    table2 = Table(info, colWidths=[160, 340])
    table2.setStyle(TableStyle([
        ("GRID", (0,0), (-1,-1), 0.5, colors.grey),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("FONTNAME", (0,0), (0,-1), "Helvetica-Bold"),
    ]))
    story.append(table2)

    doc.build(story)
    buf.seek(0)
    return StreamingResponse(
        buf,
        media_type="application/pdf",
        headers={"Content-Disposition": 'attachment; filename="website-audit.pdf"'}
    )


@app.post("/batch")
async def batch(file: UploadFile = File(...)):
    raw = await file.read()
    text = raw.decode("utf-8-sig", errors="ignore")

    urls = []
    if file.filename and file.filename.lower().endswith(".csv"):
        reader = csv.reader(text.splitlines())
        for row in reader:
            for cell in row:
                cell = cell.strip()
                if cell.startswith(("http://", "https://")):
                    urls.append(cell)
    else:
        for line in text.splitlines():
            line = line.strip()
            if line.startswith(("http://", "https://")):
                urls.append(line)

    # Preserve order while removing duplicates.
    seen = set()
    urls = [u for u in urls if not (u in seen or seen.add(u))]
    urls = urls[:50]

    # IMPORTANT: run the async scanner directly; never call asyncio.run()
    # from this already-running FastAPI event loop.
    results = await scan_many(urls)

    output = BytesIO()
    writer = csv.writer(output)
    writer.writerow([
        "url", "final_url", "status_code", "wordpress", "wp_version",
        "title", "missing_alt_count", "lead_score", "findings", "error"
    ])

    for r in results:
        finding_text = " | ".join(
            f"{severity}: {message}"
            for severity, message in findings_rows(r.get("findings", []))
        )
        writer.writerow([
            r.get("url",""),
            r.get("final_url",""),
            r.get("status_code",""),
            r.get("wordpress",""),
            r.get("wp_version",""),
            r.get("title",""),
            r.get("missing_alt_count",""),
            r.get("lead_score",""),
            finding_text,
            r.get("error",""),
        ])

    output.seek(0)
    return StreamingResponse(
        output,
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="wp-prospect-results.csv"'}
    )
