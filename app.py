from fastapi import FastAPI, Form, UploadFile, File
from fastapi.responses import HTMLResponse, StreamingResponse
from scanner import scan_site_async
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
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
    return value.rstrip("/")


def parse_urls(text: str):
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

    seen = set()
    result = []
    for url in urls:
        key = url.lower()
        if key not in seen:
            seen.add(key)
            result.append(url)

    return result[:50]


# These are the findings we consider genuinely useful for a WordPress
# prospecting conversation. Generic metadata/security observations are
# retained in the raw scan but do not inflate the sales lead score.
ACTIONABLE_TITLES = {
    "Broken internal link",
    "JavaScript runtime error detected",
    "Browser console error detected",
    "Frontend resources failed to load",
    "Possible mobile horizontal overflow",
    "Desktop horizontal overflow detected",
    "Potentially outdated WordPress version exposed",
    "Images missing ALT attributes",
    "No H1 heading detected",
    "Missing page title",
    "Missing meta description",
}

IGNORED_FOR_LEAD_SCORE = {
    "Common security headers missing",
    "WordPress readme.html publicly accessible",
    "WordPress license.txt publicly accessible",
    "WordPress REST API responds",
    "XML-RPC endpoint responds",
    "Canonical tag not detected",
    "Incomplete Open Graph metadata",
    "Twitter/X card not detected",
    "WordPress could not be confirmed",
}


def finding_text(f):
    if not isinstance(f, dict):
        return str(f)
    return str(f.get("title", ""))


def classify_result(result):
    status = result.get("status_code")
    wordpress = bool(result.get("wordpress"))
    title = (result.get("title") or "").strip()
    error = (result.get("error") or "").strip()

    # 2xx/3xx responses with no usable HTML are often bot-protection,
    # challenge pages, redirects, or application responses. Do not call
    # these "not WordPress".
    inconclusive = (
        not wordpress
        and not error
        and status is not None
        and status < 400
        and not title
    )

    if inconclusive:
        scan_status = "Inconclusive"
    elif wordpress:
        scan_status = "Confirmed WordPress"
    else:
        scan_status = "Not confirmed WordPress"

    raw = result.get("findings") or []
    actionable = []

    for f in raw:
        if isinstance(f, dict):
            title_f = finding_text(f)
            if title_f in ACTIONABLE_TITLES:
                actionable.append(f)

    # Only count actionable findings. Informational/security-hardening
    # observations do not make a lead look artificially valuable.
    weights = {
        "High": 25,
        "Medium": 10,
        "Low": 3,
        "Info": 0,
    }

    score = 0
    for f in actionable:
        score += weights.get(f.get("severity", "Info"), 0)

    # Old WP core is especially useful for a WordPress maintenance pitch.
    if any(
        isinstance(f, dict)
        and f.get("title") == "Potentially outdated WordPress version exposed"
        for f in actionable
    ):
        score += 15

    score = min(score, 100)

    # Choose the strongest practical pitch angle.
    priority = [
        "Potentially outdated WordPress version exposed",
        "JavaScript runtime error detected",
        "Frontend resources failed to load",
        "Possible mobile horizontal overflow",
        "Broken internal link",
        "Browser console error detected",
        "Images missing ALT attributes",
        "No H1 heading detected",
        "Missing page title",
        "Missing meta description",
    ]

    best = None
    for wanted in priority:
        for f in actionable:
            if isinstance(f, dict) and f.get("title") == wanted:
                best = f
                break
        if best:
            break

    if best:
        pitch_angle = best.get("title", "")
        evidence = best.get("details", "")
        recommendation = best.get("recommendation", "")
    elif scan_status == "Inconclusive":
        pitch_angle = "Recheck manually"
        evidence = "The site did not return enough usable public HTML to confirm the technology."
        recommendation = "Open the site manually before contacting the owner."
    elif scan_status == "Not confirmed WordPress":
        pitch_angle = "No WordPress pitch"
        evidence = "WordPress could not be confirmed from the public scan."
        recommendation = "Do not send a WordPress-specific pitch based on this scan."
    else:
        pitch_angle = "No strong issue found"
        evidence = "No high-value actionable issue was detected by the passive scan."
        recommendation = "Skip unless manual inspection finds a stronger issue."

    result["scan_status"] = scan_status
    result["actionable_findings"] = actionable
    result["sales_lead_score"] = score
    result["pitch_angle"] = pitch_angle
    result["pitch_evidence"] = evidence
    result["pitch_recommendation"] = recommendation

    return result


def process_result(result):
    return classify_result(result)


def findings_for_display(result):
    findings = result.get("actionable_findings") or []
    if not findings:
        return ["No strong sales-relevant technical issue detected."]
    return [
        f"{f.get('severity', '')} — {f.get('title', '')}: {f.get('details', '')}"
        for f in findings
        if isinstance(f, dict)
    ]


def html_report(result):
    result = process_result(result)
    url = escape(str(result.get("url", "")), quote=True)

    rows = [
        ("URL", result.get("url", "")),
        ("Scan status", result.get("scan_status", "")),
        ("HTTP status", result.get("status_code", "")),
        ("WordPress", result.get("wordpress", "")),
        ("WP version", result.get("wp_version", "")),
        ("Title", result.get("title", "")),
        ("Missing ALT", result.get("missing_alt_count", "")),
        ("JS runtime errors", len(result.get("javascript_errors") or result.get("js_errors") or [])),
        ("Console errors", len(result.get("console_errors") or [])),
        ("Failed resources", len(result.get("failed_requests") or [])),
        ("Sales lead score", result.get("sales_lead_score", "")),
        ("Best pitch angle", result.get("pitch_angle", "")),
        ("Evidence", result.get("pitch_evidence", "")),
    ]

    table = "".join(
        f"<tr><th>{escape(str(k))}</th><td>{escape(str(v))}</td></tr>"
        for k, v in rows
    )

    items = findings_for_display(result)
    finding_html = "".join(f"<li>{escape(x)}</li>" for x in items)

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
th{{width:190px;background:#f5f5f5}}
.box{{border:1px solid #ddd;border-radius:8px;padding:16px;margin:16px 0}}
button{{padding:10px 14px;cursor:pointer}}
</style>
</head>
<body>
<h1>WP Prospect Scanner Report</h1>
<div class="box"><table>{table}</table></div>

<div class="box">
<h2>Sales-relevant findings</h2>
<ul>{finding_html}</ul>
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
<input name="url" type="text" placeholder="https://example.com" required>
<button type="submit">Scan Website</button>
</form>
</div>

<div class="card">
<h2>Bulk scan — paste URLs</h2>
<p>Paste <b>1–50 URLs</b>, one per line.</p>
<form method="post" action="/batch">
<textarea name="urls" placeholder="https://example1.com
https://example2.com
https://example3.com" required></textarea>
<button type="submit">Scan All URLs</button>
</form>
<small>Sites are scanned sequentially to keep the free Render instance stable.</small>
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
            raw = await scan_site_async(url)
            results.append(process_result(raw))
        except Exception as exc:
            results.append(process_result({
                "url": url,
                "error": f"{type(exc).__name__}: {exc}",
                "wordpress": False,
                "lead_score": 0,
                "findings": [],
            }))
    return results


def results_to_csv(results):
    output = StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "website",
        "scan_status",
        "http_status",
        "wordpress",
        "wp_version",
        "title",
        "sales_lead_score",
        "pitch_angle",
        "pitch_evidence",
        "missing_alt_count",
        "js_runtime_errors",
        "console_errors",
        "failed_resources",
        "actionable_findings",
        "scanner_error",
    ])

    for r in results:
        findings = r.get("actionable_findings") or []
        finding_text = " | ".join(
            f"{f.get('severity', '')}: {f.get('title', '')} — {f.get('details', '')}"
            for f in findings
            if isinstance(f, dict)
        )

        writer.writerow([
            r.get("url", ""),
            r.get("scan_status", ""),
            r.get("status_code", ""),
            r.get("wordpress", ""),
            r.get("wp_version", ""),
            r.get("title", ""),
            r.get("sales_lead_score", 0),
            r.get("pitch_angle", ""),
            r.get("pitch_evidence", ""),
            r.get("missing_alt_count", 0),
            len(r.get("javascript_errors") or r.get("js_errors") or []),
            len(r.get("console_errors") or []),
            len(r.get("failed_requests") or []),
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
            status_code=400,
        )

    results = await run_batch(url_list)
    data = results_to_csv(results)

    return StreamingResponse(
        BytesIO(data),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="wp-scan-results.csv"'},
    )


@app.post("/batch-file")
async def batch_file(file: UploadFile = File(...)):
    content = await file.read()
    text = content.decode("utf-8", errors="ignore")

    found = re.findall(r"https?://[^\s,;\"']+", text, flags=re.I)
    if found:
        found = parse_urls("\n".join(found))
    else:
        found = parse_urls(text)

    if not found:
        return HTMLResponse(
            "<h2>No valid URLs found.</h2><p><a href='/'>Back</a></p>",
            status_code=400,
        )

    results = await run_batch(found)
    data = results_to_csv(results)

    return StreamingResponse(
        BytesIO(data),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="wp-scan-results.csv"'},
    )


@app.post("/report")
async def report(url: str = Form(...)):
    url = clean_url(url)
    try:
        result = process_result(await scan_site_async(url))
    except Exception as exc:
        result = process_result({"url": url, "error": f"{type(exc).__name__}: {exc}"})

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    styles = getSampleStyleSheet()

    story = [
        Paragraph("WP Prospect Scanner Report", styles["Title"]),
        Spacer(1, 12),
    ]

    for key, value in [
        ("Website", result.get("url", "")),
        ("Scan status", result.get("scan_status", "")),
        ("HTTP status", result.get("status_code", "")),
        ("WordPress", result.get("wordpress", "")),
        ("WordPress version", result.get("wp_version", "")),
        ("Sales lead score", result.get("sales_lead_score", "")),
        ("Best pitch angle", result.get("pitch_angle", "")),
        ("Evidence", result.get("pitch_evidence", "")),
    ]:
        story.append(
            Paragraph(
                f"<b>{escape(str(key))}</b>: {escape(str(value))}",
                styles["BodyText"],
            )
        )
        story.append(Spacer(1, 5))

    story.append(Spacer(1, 10))
    story.append(Paragraph("Sales-relevant findings", styles["Heading2"]))

    for text in findings_for_display(result):
        story.append(Paragraph(escape(text), styles["BodyText"]))
        story.append(Spacer(1, 5))

    doc.build(story)
    buffer.seek(0)

    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": 'attachment; filename="wp-prospect-report.pdf"'},
    )


@app.get("/report-html", response_class=HTMLResponse)
async def report_html(url: str):
    url = clean_url(url)
    try:
        result = process_result(await scan_site_async(url))
    except Exception as exc:
        result = process_result({"url": url, "error": f"{type(exc).__name__}: {exc}"})
    return html_report(result)
