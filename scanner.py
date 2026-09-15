import asyncio
import re
import time
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright

TIMEOUT = 20
MAX_HTML_SIZE = 3_000_000
USER_AGENT = "Mozilla/5.0 (compatible; WP-Prospect-Scanner/2.0; Passive Website Audit)"


def normalize_url(url):
    url = (url or "").strip()
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


def add_finding(findings, severity, category, title, details, recommendation):
    findings.append({
        "severity": severity,
        "category": category,
        "title": title,
        "details": details,
        "recommendation": recommendation,
    })


def same_domain(a, b):
    aa = urlparse(a).netloc.lower().replace("www.", "")
    bb = urlparse(b).netloc.lower().replace("www.", "")
    return aa == bb


def detect_wordpress(html, response):
    text = html.decode("utf-8", errors="ignore").lower()
    indicators = []

    if "wordpress" in text:
        indicators.append("WordPress reference in HTML")
    if "/wp-content/" in text:
        indicators.append("/wp-content/ detected")
    if "/wp-includes/" in text:
        indicators.append("/wp-includes/ detected")
    if "api.w.org" in text:
        indicators.append("WordPress REST API reference")

    if response:
        redirect_header = response.headers.get("x-redirect-by", "")
        if "wordpress" in redirect_header.lower():
            indicators.append("X-Redirect-By: WordPress")

    return bool(indicators), indicators


def extract_wp_version(soup):
    tag = soup.find("meta", attrs={"name": re.compile("^generator$", re.I)})
    if not tag:
        return None
    content = tag.get("content", "")
    match = re.search(r"WordPress\s+([0-9]+(?:\.[0-9]+){1,3})", content, re.I)
    return match.group(1) if match else None


def extract_theme_and_plugins(html):
    text = html.decode("utf-8", errors="ignore")
    themes = set()
    plugins = set()

    for match in re.findall(r"/wp-content/themes/([^/\"'?]+)", text, re.I):
        if match not in ("*", ""):
            themes.add(match)

    for match in re.findall(r"/wp-content/plugins/([^/\"'?]+)", text, re.I):
        if match not in ("*", ""):
            plugins.add(match)

    return sorted(themes), sorted(plugins)


def analyze_html(soup):
    findings = []
    title = soup.title.get_text(" ", strip=True) if soup.title else ""

    description_tag = soup.find(
        "meta", attrs={"name": re.compile("^description$", re.I)}
    )
    description = description_tag.get("content", "").strip() if description_tag else ""

    canonical = soup.find(
        "link", attrs={"rel": lambda value: value and "canonical" in value}
    )
    og_title = soup.find("meta", attrs={"property": re.compile("^og:title$", re.I)})
    og_description = soup.find(
        "meta", attrs={"property": re.compile("^og:description$", re.I)}
    )
    og_image = soup.find("meta", attrs={"property": re.compile("^og:image$", re.I)})
    twitter_card = soup.find(
        "meta", attrs={"name": re.compile("^twitter:card$", re.I)}
    )

    h1s = soup.find_all("h1")
    images = soup.find_all("img")
    missing_alt = [img.get("src", "")[:200] for img in images if img.get("alt") is None]

    if not title:
        add_finding(
            findings, "High", "SEO", "Missing page title",
            "The page does not contain a detectable HTML title.",
            "Add a unique, descriptive title tag."
        )
    elif len(title) > 65:
        add_finding(
            findings, "Medium", "SEO", "Long page title",
            f"The title contains approximately {len(title)} characters.",
            "Review and shorten the title where appropriate."
        )

    if not description:
        add_finding(
            findings, "Medium", "SEO", "Missing meta description",
            "No standard meta description was detected.",
            "Add a concise description for important pages."
        )

    if not canonical:
        add_finding(
            findings, "Low", "SEO", "Canonical tag not detected",
            "No canonical link element was detected.",
            "Review whether a canonical URL should be specified."
        )

    if not og_title or not og_description or not og_image:
        missing_og = []
        if not og_title:
            missing_og.append("og:title")
        if not og_description:
            missing_og.append("og:description")
        if not og_image:
            missing_og.append("og:image")
        add_finding(
            findings, "Low", "Social", "Incomplete Open Graph metadata",
            "Missing: " + ", ".join(missing_og),
            "Add the missing Open Graph fields so shared links have better previews."
        )

    if not twitter_card:
        add_finding(
            findings, "Low", "Social", "Twitter/X card not detected",
            "No Twitter/X card metadata was detected.",
            "Consider adding appropriate social-card metadata."
        )

    if len(h1s) == 0:
        add_finding(
            findings, "Medium", "Accessibility", "No H1 heading detected",
            "No H1 element was found on the scanned page.",
            "Review the page heading structure."
        )
    elif len(h1s) > 1:
        add_finding(
            findings, "Low", "Accessibility", "Multiple H1 headings",
            f"{len(h1s)} H1 elements were detected.",
            "Review whether the heading hierarchy accurately represents the page."
        )

    if missing_alt:
        add_finding(
            findings, "Medium", "Accessibility", "Images missing ALT attributes",
            f"{len(missing_alt)} image(s) do not contain an ALT attribute.",
            "Review decorative versus meaningful images and add appropriate ALT text where needed."
        )

    return {
        "title": title,
        "description": description,
        "canonical": canonical.get("href", "") if canonical else "",
        "h1_count": len(h1s),
        "image_count": len(images),
        "missing_alt_count": len(missing_alt),
        "findings": findings,
    }


def security_headers(response):
    expected = [
        "strict-transport-security",
        "content-security-policy",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "permissions-policy",
    ]
    headers = {k.lower(): v for k, v in response.headers.items()}
    return [h for h in expected if h not in headers]


async def fetch_endpoint(client, origin, path):
    try:
        response = await client.get(
            origin + path, follow_redirects=True, timeout=TIMEOUT
        )
        return {
            "status": response.status_code,
            "accessible": response.status_code < 400,
        }
    except Exception as exc:
        return {"status": None, "accessible": False, "error": str(exc)}


async def endpoint_scan(client, base_url):
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    endpoints = {
        "wp_json": "/wp-json/",
        "xmlrpc": "/xmlrpc.php",
        "readme": "/readme.html",
        "license": "/license.txt",
        "wp_login": "/wp-login.php",
    }
    results = {}
    for name, path in endpoints.items():
        results[name] = await fetch_endpoint(client, origin, path)
    return results


async def check_links(client, base_url, soup, limit=25):
    links = []
    for anchor in soup.find_all("a", href=True):
        href = anchor["href"].strip()
        if href.startswith(("#", "mailto:", "tel:", "javascript:")):
            continue
        absolute = urljoin(base_url, href)
        if not same_domain(base_url, absolute):
            continue
        if absolute not in links:
            links.append(absolute)
        if len(links) >= limit:
            break

    broken = []
    for link in links:
        try:
            response = await client.get(
                link, follow_redirects=True, timeout=10
            )
            if response.status_code >= 400:
                broken.append({"url": link, "status": response.status_code})
        except Exception:
            broken.append({"url": link, "status": "error"})
    return broken


async def browser_scan(url):
    result = {
        "console_errors": [],
        "failed_requests": [],
        "javascript_errors": [],
        "layout": {"desktop": {}, "mobile": {}},
        "timing": {},
    }

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
        )

        page = await browser.new_page(
            viewport={"width": 1366, "height": 768}
        )

        console_errors = []
        failed_requests = []
        javascript_errors = []

        page.on(
            "console",
            lambda msg: console_errors.append(msg.text)
            if msg.type == "error" else None
        )
        page.on(
            "requestfailed",
            lambda request: failed_requests.append({
                "url": request.url,
                "error": request.failure,
                "resource_type": request.resource_type,
            })
        )
        page.on(
            "pageerror",
            lambda exc: javascript_errors.append(str(exc))
        )

        start = time.time()

        try:
            response = await page.goto(
                url, wait_until="domcontentloaded", timeout=25000
            )
            try:
                await page.wait_for_load_state("networkidle", timeout=8000)
            except Exception:
                pass

            result["timing"]["domcontentloaded_seconds"] = round(
                time.time() - start, 2
            )
            if response:
                result["browser_status"] = response.status
        except Exception as exc:
            result["browser_error"] = str(exc)

        result["console_errors"] = console_errors[:30]
        result["javascript_errors"] = javascript_errors[:30]
        result["failed_requests"] = [
            {
                "url": item["url"],
                "resource_type": item["resource_type"],
                "error": str(item["error"]),
            }
            for item in failed_requests[:50]
        ]

        async def layout_test():
            return await page.evaluate("""
                () => {
                    const viewportWidth = window.innerWidth;
                    const viewportHeight = window.innerHeight;
                    const overflowing = [];
                    const outside = [];

                    document.querySelectorAll('body *').forEach((el) => {
                        const r = el.getBoundingClientRect();

                        if (r.width > 0 && r.right > viewportWidth + 5) {
                            overflowing.push({
                                tag: el.tagName,
                                className:
                                    typeof el.className === 'string'
                                    ? el.className.slice(0, 120) : '',
                                right: Math.round(r.right),
                                width: Math.round(r.width)
                            });
                        }

                        if (r.width > 0 && r.left < -5) {
                            outside.push({
                                tag: el.tagName,
                                left: Math.round(r.left)
                            });
                        }
                    });

                    return {
                        viewportWidth,
                        viewportHeight,
                        documentWidth: document.documentElement.scrollWidth,
                        bodyWidth: document.body.scrollWidth,
                        horizontalOverflow:
                            document.documentElement.scrollWidth > viewportWidth + 5,
                        overflowingElements: overflowing.slice(0, 20),
                        elementsOutsideViewport: outside.slice(0, 20)
                    };
                }
            """)

        result["layout"]["desktop"] = await layout_test()

        await page.set_viewport_size({"width": 390, "height": 844})
        try:
            await page.reload(
                wait_until="domcontentloaded", timeout=20000
            )
        except Exception:
            pass

        await page.wait_for_timeout(1500)
        result["layout"]["mobile"] = await layout_test()

        await browser.close()

    return result


async def scan_site_async(url):
    url = normalize_url(url)
    if not url:
        return {"url": "", "error": "Empty URL"}

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml",
    }

    async with httpx.AsyncClient(headers=headers, verify=True) as client:
        try:
            response = await client.get(
                url, follow_redirects=True, timeout=TIMEOUT
            )
        except Exception as exc:
            return {"url": url, "error": f"Connection failed: {exc}"}

        html = response.content[:MAX_HTML_SIZE]
        final_url = str(response.url)
        soup = BeautifulSoup(html, "html.parser")

        wordpress, indicators = detect_wordpress(html, response)
        wp_version = extract_wp_version(soup)
        themes, plugins = extract_theme_and_plugins(html)
        html_data = analyze_html(soup)
        findings = html_data["findings"]

        missing_headers = security_headers(response)
        endpoints = await endpoint_scan(client, final_url)
        broken_links = await check_links(client, final_url, soup)

        if missing_headers:
            add_finding(
                findings, "Low", "Security", "Common security headers missing",
                f"{len(missing_headers)} commonly used security header(s) were not detected.",
                "Review the site's security-header configuration."
            )

        if endpoints["readme"]["accessible"]:
            add_finding(
                findings, "Low", "WordPress",
                "WordPress readme.html publicly accessible",
                "The standard WordPress readme file responds publicly.",
                "Consider whether public access to this file is necessary."
            )

        if endpoints["license"]["accessible"]:
            add_finding(
                findings, "Info", "WordPress",
                "WordPress license.txt publicly accessible",
                "The standard license file responds publicly.",
                "Usually informational; remove only if appropriate."
            )

        if endpoints["wp_json"]["accessible"]:
            add_finding(
                findings, "Info", "WordPress",
                "WordPress REST API responds",
                "The public REST API endpoint responds successfully.",
                "Review exposed data and API configuration if this is a security-hardening project."
            )

        if endpoints["xmlrpc"]["accessible"]:
            add_finding(
                findings, "Info", "WordPress",
                "XML-RPC endpoint responds",
                "The XML-RPC endpoint is publicly reachable.",
                "Review whether XML-RPC is required by the site's functionality."
            )

        for broken in broken_links[:15]:
            add_finding(
                findings, "High", "Links", "Broken internal link",
                f"{broken['status']} response from {broken['url']}",
                "Repair or remove the broken internal link."
            )

        try:
            browser = await browser_scan(final_url)
        except Exception as exc:
            browser = {
                "browser_error": str(exc),
                "console_errors": [],
                "failed_requests": [],
                "javascript_errors": [],
                "layout": {},
                "timing": {},
            }

        for error in browser.get("javascript_errors", []):
            add_finding(
                findings, "High", "JavaScript",
                "JavaScript runtime error detected",
                error[:500],
                "Inspect the JavaScript error in the browser console and repair the affected script."
            )

        for error in browser.get("console_errors", []):
            add_finding(
                findings, "Medium", "JavaScript",
                "Browser console error detected",
                error[:500],
                "Review the console error and verify whether it affects site functionality."
            )

        failed = browser.get("failed_requests", [])
        important_failed = [
            x for x in failed
            if x.get("resource_type")
            in ("script", "stylesheet", "image", "font")
        ]

        if important_failed:
            add_finding(
                findings, "High", "Frontend",
                "Frontend resources failed to load",
                f"{len(important_failed)} CSS, JavaScript, image or font request(s) failed.",
                "Inspect the failed resources and repair missing or inaccessible assets."
            )

        mobile = browser.get("layout", {}).get("mobile", {})
        desktop = browser.get("layout", {}).get("desktop", {})

        if mobile.get("horizontalOverflow"):
            add_finding(
                findings, "High", "Mobile",
                "Possible mobile horizontal overflow",
                "The document is wider than the 390px mobile viewport.",
                "Inspect the page at mobile width and fix overflowing elements."
            )

        if desktop.get("horizontalOverflow"):
            add_finding(
                findings, "Medium", "Layout",
                "Desktop horizontal overflow detected",
                "The document extends beyond the desktop viewport.",
                "Inspect oversized or incorrectly positioned elements."
            )

        if wp_version and wp_version.startswith(("4.", "5.")):
            add_finding(
                findings, "High", "WordPress",
                "Potentially outdated WordPress version exposed",
                f"Detected WordPress version: {wp_version}.",
                "Review the WordPress core version and update safely after checking theme/plugin compatibility."
            )

        if not wordpress:
            add_finding(
                findings, "Info", "Technology",
                "WordPress could not be confirmed",
                "The scanner did not find enough public indicators to confidently identify WordPress.",
                "No WordPress-specific sales pitch should be based on this scan."
            )

        score = calculate_score(
            findings, wordpress, wp_version, browser
        )

        return {
            "url": url,
            "final_url": final_url,
            "status_code": response.status_code,
            "wordpress": wordpress,
            "wp_indicators": indicators,
            "wp_version": wp_version,
            "themes": themes,
            "plugins": plugins,
            "title": html_data["title"],
            "description": html_data["description"],
            "canonical": html_data["canonical"],
            "h1_count": html_data["h1_count"],
            "image_count": html_data["image_count"],
            "missing_alt_count": html_data["missing_alt_count"],
            "missing_security_headers": missing_headers,
            "special_endpoints": endpoints,
            "broken_links": broken_links,
            "browser": browser,
            "findings": findings,
            "lead_score": score,
            "error": "",
        }


def calculate_score(findings, wordpress, wp_version, browser):
    if not wordpress:
        return 0

    score = 10
    weights = {"High": 15, "Medium": 8, "Low": 3, "Info": 0}

    for finding in findings:
        score += weights.get(finding["severity"], 0)

    if wp_version:
        try:
            parts = wp_version.split(".")
            major = int(parts[0])
            minor = int(parts[1])
            if major <= 5:
                score += 20
            elif major == 6 and minor < 5:
                score += 8
        except Exception:
            pass

    failed = len(browser.get("failed_requests", []))
    if failed:
        score += min(failed * 2, 10)

    return min(score, 100)


def scan_site(url):
    return asyncio.run(scan_site_async(url))


def scan_many(urls):
    results = []
    for url in urls:
        try:
            results.append(scan_site(url))
        except Exception as exc:
            results.append({
                "url": url,
                "error": str(exc),
                "lead_score": 0,
            })
    return results
