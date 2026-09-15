from fastapi import FastAPI, Form, UploadFile, File
from fastapi.responses import HTMLResponse, StreamingResponse
from scanner import scan_site_async
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from io import BytesIO, StringIO
from html import escape
import csv
import re

app = FastAPI(title="WP Prospect Scanner")


def clean_url(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    if not re.match(r"^https?://", value, re.I):
        value = "https://" + value
    return value


def parse_urls(text: str):
    # One URL per line is the primary format.
    # Also accept comma/semicolon-separated input for convenience.
    raw_lines = re.split(r"[\r\n]+", text or "")
    urls = []

    for line in raw_lines:
        line = line.strip()
        if not line:
            continue

        parts = [line]
        if "://" not in line and ("," in line or ";" in line):
            parts = re.split(r"[,;]+", line)

        for part in parts:
            url = clean_url(part)
            if url and re.match(r"^https?://", url, re.I):
                urls.append(url)

    # Preserve order while removing duplicates.
    seen = set()
    result = []
    for url in urls:
        key = url.rstrip("/").lower()
        if key not in seen:
            seen.add(key)
            result.append(url)

    return result[:50]


def result_rows(result):
    findings = result.get("findings") or []
    return [
        ("URL", result.get("url", "")),
        ("Final URL", result.get("final_url", "")),
        ("HTTP status", result.get("status_code", "")),
        ("WordPress", result.get("wordpress", "")),
        ("WP version", result.get("wp_version", "")),
        ("Title", result.get("title", "")),
        ("Missing ALT", result.get("missing_alt_count", "")),
        ("JS errors", len(result.get("js_errors") or [])),
        ("Console errors", len(result.get("console_errors") or [])),
        ("Failed resources", len(result.get("failed_requests") or [])),
        ("Lead score", result.get("lead_score", "")),
        ("Findings", "; ".join(
            f"{x[0]}: {x[1]}" if isinstance(x, (list, tuple)) and len(x) >= 2 else str(x)
            for x in findings
        )),
        ("Error", result.get("error", "")),
    ]


def html_report(result):
    rows = result_rows(result)
    findings = result.get("findings") or []

    finding_html = ""
    for item in findings:
        if isinstance(item, (list, tuple)) and len(item) >= 2:
            level = escape(str(item[0]))
            text = escape(str(item[1]))
            finding_html += f"<li><b>{level}</b> — {text}</li>"
        else:
            finding_html += f"<li>{escape(str(item))}</li>"

    if not finding_html:
        finding_html = "<li>No findings recorded.</li>"

    js_errors = result.get("js_errors") or []
    console_errors = result.get("console_errors") or []
    failed_requests = result.get("failed_requests") or []

    def list_html(items):
        if not items:
            return "<li>None detected.</li>"
        return "".join(f"<li>{escape(str(x))}</li>" for x in items[:30])

    table = "".join(
        f"<tr><th>{escape(str(k))}</th><td>{escape(str(v))}</td></tr>"
        for k, v in rows
    )

    url = escape(str(result.get("url", "")), quote=True)

    return f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WP Prospect Scanner Report</title>
<style>
body{{font-family:Arial,sans-serif;max-width:1000px;margin:30px auto;padding:0 16px;line-height:1.5}}
table{{border-collapse:collapse;width:100%;margin:20px 0}}
th,td{{border:1px solid #ddd;padding:8px;text-align:left;vertical-align:top}}
th{{width:180px;background:#f5f5f5}}
.box{{border:1px solid #ddd;border-radius:8px;padding:16px;margin:16px 0}}
button{{padding:10px 14px;cursor:pointer}}
a{{text-decoration:none}}
</style>
</head>
<body>
<h1>WP Prospect Scanner</h1>
<div class="box">
<table>{table}</table>
</div>

<div class="box">
<h2>Findings</h2>
<ul>{finding_html}</ul>
</div>

<div class="box">
<h2>JavaScript errors</h2>
<ul>{list_html(js_errors)}</ul>
<h2>Console errors</h2>
<ul>{list_html(console_errors)}</ul>
<h2>Failed resources</h2>
<ul>{list_html(failed_requests)}</ul>
</div>

<form method="post" action="/report">
<input type="hidden" name="url" value="{url}">
<button type="submit">Download PDF report</button>
</form>
<p><a href="/">← Back to scanner</a></p>
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
body{font-family:Arial,sans-serif;max-width:900px;margin:30px auto;padding:0 16px;line-height:1.5}
.card{border:1px solid #ddd;border-radius:10px;padding:20px;margin:20px 0}
input,textarea{width:100%;box-sizing:border-box;padding:10px;margin:8px 0 14px}
textarea{min-height:260px;font-family:monospace}
button{padding:11px 16px;cursor:pointer}
small{color:#666}
</style>
</head>
<body>
<h1>WP Prospect Scanner</h1>

<div class="card">
<h2>Single website</h2>
<form method="post" action="/scan">
<label>Website URL</label>
<input name="url" type="text" placeholder="https://example.com" required>
<button type="submit">Scan Website</button>
</form>
</div>

<div class="card">
<h2>Bulk scan — paste URLs</h2>
<p>Paste <b>1–50 URLs</b>, one per line. No TXT/CSV upload is required.</p>
<form method="post" action="/batch">
<textarea name="urls" placeholder="https://example1.com
https://example2.com
https://example3.com" required></textarea>
<button type="submit">Scan All URLs</button>
</form>
<small>The scanner processes the sites sequentially to reduce memory pressure on the free Render instance.</small>
</div>

<div class="card">
<h2>Bulk scan — TXT/CSV upload</h2>
<form method="post" action="/batch-file" enctype="multipart/form-data">
<input type="file" name="file" accept=".txt,.csv" required>
<button type="submit">Upload and Scan</button>
</form>
</div>
</body>
</html>"""


@app.post("/scan", response_class=HTMLResponse)
async def scan(url: str = Form(...)):
    url = clean_url(url)
    try:
        result = await scan_site_async(url)
    except Exception as exc:
        result = {"url": url, "error": f"{type(exc).__name__}: {exc}"}
    return html_report(result)


async def run_batch(urls):
    results = []
    for url in urls:
        try:
            result = await scan_site_async(url)
        except Exception as exc:
            result = {
                "url": url,
                "error": f"{type(exc).__name__}: {exc}",
                "wordpress": False,
                "lead_score": 0,
                "findings": [],
            }
        results.append(result)
    return results


def results_to_csv(results):
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "url", "final_url", "status_code", "wordpress", "wp_version",
        "title", "missing_alt_count", "js_errors", "console_errors",
        "failed_resources", "lead_score", "findings", "error"
    ])

    for r in results:
        findings = r.get("findings") or []
        finding_text = " | ".join(
            f"{x[0]}: {x[1]}" if isinstance(x, (list, tuple)) and len(x) >= 2 else str(x)
            for x in findings
        )
        writer.writerow([
            r.get("url", ""),
            r.get("final_url", ""),
            r.get("status_code", ""),
            r.get("wordpress", ""),
            r.get("wp_version", ""),
            r.get("title", ""),
            r.get("missing_alt_count", ""),
            len(r.get("js_errors") or []),
            len(r.get("console_errors") or []),
            len(r.get("failed_requests") or []),
            r.get("lead_score", ""),
            finding_text,
            r.get("error", ""),
        ])

    return output.getvalue().encode("utf-8-sig")


@app.post("/batch")
async def batch(urls: str = Form(...)):
    url_list = parse_urls(urls)

    if not url_list:
        return HTMLResponse(
            "<h2>No valid URLs found.</h2><p><a href='/'>Back</a></p>",
            status_code=400
        )

    results = await run_batch(url_list)
    data = results_to_csv(results)

    return StreamingResponse(
        BytesIO(data),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": 'attachment; filename="wp-scan-results.csv"'
        },
    )


@app.post("/batch-file")
async def batch_file(file: UploadFile = File(...)):
    content = await file.read()
    text = content.decode("utf-8", errors="ignore")

    # For CSV files, extract URL-looking cells; for TXT this also works.
    found = re.findall(r"https?://[^\s,;\"']+", text, flags=re.I)
    if not found:
        # Fall back to line-based parsing for domains without a scheme.
        found = parse_urls(text)
    else:
        found = parse_urls("\n".join(found))

    if not found:
        return HTMLResponse(
            "<h2>No valid URLs found in the uploaded file.</h2><p><a href='/'>Back</a></p>",
            status_code=400
        )

    results = await run_batch(found)
    data = results_to_csv(results)

    return StreamingResponse(
        BytesIO(data),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": 'attachment; filename="wp-scan-results.csv"'
        },
    )


@app.post("/report")
async def report(url: str = Form(...)):
    url = clean_url(url)
    try:
        result = await scan_site_async(url)
    except Exception as exc:
        result = {"url": url, "error": f"{type(exc).__name__}: {exc}"}

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    styles = getSampleStyleSheet()
    story = [
        Paragraph("WP Prospect Scanner Report", styles["Title"]),
        Spacer(1, 12),
    ]

    for key, value in result_rows(result):
        story.append(Paragraph(
            f"<b>{escape(str(key))}</b>: {escape(str(value))}",
            styles["BodyText"]
        ))
        story.append(Spacer(1, 5))

    findings = result.get("findings") or []
    if findings:
        story.append(Spacer(1, 10))
        story.append(Paragraph("Findings", styles["Heading2"]))
        for item in findings:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                text = f"{item[0]} — {item[1]}"
            else:
                text = str(item)
            story.append(Paragraph(escape(text), styles["BodyText"]))
            story.append(Spacer(1, 4))

    doc.build(story)
    buffer.seek(0)

    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={
            "Content-Disposition": 'attachment; filename="wp-prospect-report.pdf"'
        },
    )


@app.get("/report-html", response_class=HTMLResponse)
async def report_html(url: str):
    url = clean_url(url)
    try:
        result = await scan_site_async(url)
    except Exception as exc:
        result = {"url": url, "error": f"{type(exc).__name__}: {exc}"}
    return html_report(result)
