from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse, JSONResponse

from scanner import scan_site


app = FastAPI(
    title="WP Prospect Scanner",
    version="1.0"
)


HTML = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>WP Prospect Scanner</title>

    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 900px;
            margin: 40px auto;
            padding: 20px;
            background: #f5f5f5;
        }

        .box {
            background: white;
            padding: 25px;
            border-radius: 12px;
        }

        input {
            width: 100%;
            padding: 12px;
            box-sizing: border-box;
            margin: 8px 0;
            border: 1px solid #ccc;
            border-radius: 6px;
        }

        button {
            padding: 12px 20px;
            border: 0;
            border-radius: 6px;
            cursor: pointer;
            background: #222;
            color: white;
        }

        pre {
            background: #111;
            color: #eee;
            padding: 20px;
            overflow-x: auto;
            border-radius: 8px;
        }
    </style>
</head>

<body>

<div class="box">

<h1>WP Prospect Scanner</h1>

<p>
Passive WordPress and technical prospect analysis.
</p>

<form method="post" action="/scan">

<input
    name="url"
    placeholder="https://example.com"
    required
>

<button type="submit">
    Scan Website
</button>

</form>

</div>

</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
def home():
    return HTML


@app.post("/scan")
def scan(url: str = Form(...)):

    result = scan_site(url)

    return JSONResponse(
        content=result
    )
