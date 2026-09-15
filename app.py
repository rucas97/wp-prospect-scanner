import csv
import io
from html import escape

from fastapi import FastAPI, Form, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse, Response

from reportlab.lib.pagesizes import A4
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
)
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet

from scanner import scan_site, scan_many

app = FastAPI(title="WP Prospect Scanner", version="2.0")

HOME = """
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WP Prospect Scanner</title>
<style>
body{font-family:Arial,sans-serif;max-width:1100px;margin:30px auto;padding:20px;background:#f3f4f6}
.card{background:white;padding:25px;margin-bottom:20px;border-radius:12px;box-shadow:0 2px 10px rgba(0,0,0,.05)}
h1{margin-top:0}
textarea{width:100%;min-height:180px;padding:12px;box-sizing:border-box;border:1px solid #ccc;border-radius:8px}
button{background:#111827;color:white;border:0;padding:12px 20px;border-radius:7px;cursor:pointer;margin-top:10px}
input[type=file]{margin-top:10px}
small{color:#666}
a.button{display:inline-block;background:#111827;color:white;padding:10px 14px;border-radius:7px;text-decoration:none;margin:5px 0}
</style>
</head>
<body>
<div class="card">
<h1>WP Prospect Scanner</h1>
<p>Passive WordPress, frontend, SEO, accessibility and technical prospect analysis.</p>
<h3>Quick scan</h3>
<form method="post" action="/scan">
<textarea name="url" placeholder="https://example.com" required></textarea>
<br><button type="submit">Scan Website</button>
</form>
</div>
<div class="card">
<h3>Batch scan</h3>
<p>Upload a TXT or CSV file containing one website URL per line. Up to 50 URLs per batch.</p>
<form method="post" action="/batch" enctype="multipart/form-data">
<input type="file" name="file" accept=".txt,.csv" required>
<br><button type="submit">Scan All Websites</button>
</form>
</div>
</body>
</html>
"""


def severity_order(value):
    return {"High": 0, "Medium": 1, "Low": 2, "Info": 3}.get(value, 4)


def report_html(result):
    findings = sorted(
        result.get("findings", []),
        key=lambda x: severity_order(x["severity"])
    )

    rows = ""
    for finding in findings:
        rows += f"""
        <tr>
        <td><b>{escape(finding['severity'])}</b></td>
        <td>{escape(finding['category'])}</td>
        <td>{escape(finding['title'])}</td>
        <td>{escape(finding['details'])}</td>
        <td>{escape(finding['recommendation'])}</td>
        </tr>
        """

    browser = result.get("browser", {})
    layout = browser.get("layout", {})

    return f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Website Audit - {escape(result.get('url',''))}</title>
<style>
body{{font-family:Arial,sans-serif;margin:40px;color:#222}}
h1{{margin-bottom:5px}}
.score{{font-size:32px;font-weight:bold}}
table{{border-collapse:collapse;width:100%;margin-top:20px}}
th,td{{border:1px solid #ddd;padding:8px;vertical-align:top;font-size:12px}}
th{{background:#f0f0f0}}
.meta{{margin:20px 0;padding:15px;background:#f5f5f5}}
</style>
</head>
<body>
<h1>Website Technical Audit</h1>
<p><b>Website:</b> {escape(result.get('final_url', result.get('url','')))}</p>
<div class="meta">
<div class="score">Lead Score: {result.get('lead_score',0)}/100</div>
<p><b>WordPress:</b> {'Confirmed' if result.get('wordpress') else 'Not confirmed'}</p>
<p><b>WordPress version:</b> {escape(str(result.get('wp_version') or 'Not publicly detected'))}</p>
<p><b>HTTP status:</b> {result.get('status_code','')}</p>
</div>
<h2>Technical Findings</h2>
<table>
<tr><th>Severity</th><th>Category</th><th>Finding</th><th>Observation</th><th>Recommended action</th></tr>
{rows}
</table>
<h2>Technology</h2>
<p><b>Themes:</b> {escape(', '.join(result.get('themes', [])) or 'Not detected')}</p>
<p><b>Plugins:</b> {escape(', '.join(result.get('plugins', [])) or 'Not detected')}</p>
<h2>Page Information</h2>
<p><b>Title:</b> {escape(result.get('title',''))}</p>
<p><b>Meta description:</b> {escape(result.get('description','')[:500])}</p>
<p><b>H1 count:</b> {result.get('h1_count',0)}</p>
<p><b>Images:</b> {result.get('image_count',0)}</p>
<p><b>Images without ALT:</b> {result.get('missing_alt_count',0)}</p>
<h2>Browser Testing</h2>
<p><b>JavaScript runtime errors:</b> {len(browser.get('javascript_errors',[]))}</p>
<p><b>Console errors:</b> {len(browser.get('console_errors',[]))}</p>
<p><b>Failed resources:</b> {len(browser.get('failed_requests',[]))}</p>
<p><b>Mobile horizontal overflow:</b> {layout.get('mobile',{}).get('horizontalOverflow',False)}</p>
<p><b>Desktop horizontal overflow:</b> {layout.get('desktop',{}).get('horizontalOverflow',False)}</p>
<p><b>DOM content load:</b> {browser.get('timing',{}).get('domcontentloaded_seconds','N/A')} seconds</p>
<hr>
<p>This report is based on publicly accessible website behaviour. Findings should be manually verified before making security, accessibility or business-critical claims.</p>
</body>
</html>
"""


def make_pdf(result):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=30
    )
    styles = getSampleStyleSheet()
    story = [
        Paragraph("Website Technical Audit", styles["Title"]),
        Spacer(1, 12),
        Paragraph(
            f"<b>Website:</b> {escape(result.get('final_url', result.get('url','')))}",
            styles["Normal"]
        ),
        Paragraph(
            f"<b>Lead Score:</b> {result.get('lead_score',0)}/100",
            styles["Heading2"]
        ),
        Paragraph(
            f"<b>WordPress:</b> {'Confirmed' if result.get('wordpress') else 'Not confirmed'}",
            styles["Normal"]
        ),
        Paragraph(
            f"<b>Detected WP version:</b> {escape(str(result.get('wp_version') or 'Not publicly detected'))}",
            styles["Normal"]
        ),
        Spacer(1, 15),
    ]

    data = [["Severity", "Category", "Finding"]]
    findings = sorted(
        result.get("findings", []),
        key=lambda x: severity_order(x["severity"])
    )

    for finding in findings[:60]:
        data.append([
            finding["severity"],
            finding["category"],
            Paragraph(
                f"<b>{escape(finding['title'])}</b><br/>"
                f"{escape(finding['details'])}<br/>"
                f"<i>Action: {escape(finding['recommendation'])}</i>",
                styles["BodyText"]
            )
        ])

    table = Table(data, colWidths=[55, 75, 390], repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0),colors.lightgrey),
        ("GRID",(0,0),(-1,-1),0.5,colors.grey),
        ("VALIGN",(0,0),(-1,-1),"TOP"),
        ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
        ("FONTSIZE",(0,0),(-1,-1),8),
        ("TOPPADDING",(0,0),(-1,-1),5),
        ("BOTTOMPADDING",(0,0),(-1,-1),5),
    ]))
    story.append(table)
    story.append(Spacer(1, 15))
    story.append(Paragraph(
        "This report is based on publicly accessible website behaviour. "
        "Findings should be manually verified before making security or "
        "business-critical claims.",
        styles["Small"]
    ))
    doc.build(story)
    return buffer.getvalue()


def extract_urls(text):
    urls = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.lower() in ("url", "website", "website_url"):
            continue
        if "," in line:
            first = line.split(",")[0].strip()
            if first.startswith(("http://", "https://")):
                line = first
        if not line.startswith(("http://", "https://")):
            line = "https://" + line
        urls.append(line)
    return list(dict.fromkeys(urls))


@app.get("/", response_class=HTMLResponse)
async def home():
    return HOME


@app.post("/scan")
async def scan(url: str = Form(...)):
    result = scan_site(url)
    return HTMLResponse(report_html(result))


@app.post("/batch")
async def batch(file: UploadFile = File(...)):
    content = await file.read()
    text = content.decode("utf-8", errors="ignore")
    urls = extract_urls(text)

    if not urls:
        return JSONResponse(
            {"error": "No URLs were found in the uploaded file."},
            status_code=400
        )

    urls = urls[:50]
    results = scan_many(urls)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "URL","Final URL","WordPress","WP Version","Lead Score",
        "Findings","High","Medium","Low","JavaScript Errors",
        "Console Errors","Failed Resources","Mobile Overflow",
        "Desktop Overflow","Broken Links"
    ])

    for result in results:
        findings = result.get("findings", [])
        high = sum(1 for x in findings if x["severity"] == "High")
        medium = sum(1 for x in findings if x["severity"] == "Medium")
        low = sum(1 for x in findings if x["severity"] == "Low")
        browser = result.get("browser", {})
        layout = browser.get("layout", {})

        writer.writerow([
            result.get("url",""),
            result.get("final_url",""),
            result.get("wordpress",False),
            result.get("wp_version",""),
            result.get("lead_score",0),
            len(findings),
            high, medium, low,
            len(browser.get("javascript_errors",[])),
            len(browser.get("console_errors",[])),
            len(browser.get("failed_requests",[])),
            layout.get("mobile",{}).get("horizontalOverflow",False),
            layout.get("desktop",{}).get("horizontalOverflow",False),
            len(result.get("broken_links",[])),
        ])

    return Response(
        content=output.getvalue().encode("utf-8"),
        media_type="text/csv",
        headers={
            "Content-Disposition":
            'attachment; filename="wp-prospect-results.csv"'
        }
    )


@app.post("/report")
async def report(url: str = Form(...)):
    result = scan_site(url)
    pdf = make_pdf(result)
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={
            "Content-Disposition":
            'attachment; filename="website-audit.pdf"'
        }
    )


@app.get("/report-html")
async def report_html_endpoint(url: str):
    result = scan_site(url)
    return HTMLResponse(report_html(result))
