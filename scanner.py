import re
import csv
import io
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup


TIMEOUT = 15
MAX_HTML_SIZE = 2_000_000
USER_AGENT = (
    "Mozilla/5.0 (compatible; WP-Prospect-Scanner/1.0; "
    "+https://github.com/rucas97/wp-prospect-scanner)"
)


def normalize_url(url: str) -> str:
    url = url.strip()

    if not url:
        return ""

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    return url.rstrip("/")


def fetch(client, url):
    try:
        response = client.get(
            url,
            follow_redirects=True,
            timeout=TIMEOUT,
        )

        content = response.content[:MAX_HTML_SIZE]

        return response, content

    except Exception as e:
        return None, b""


def same_domain(url1, url2):
    a = urlparse(url1).netloc.lower().replace("www.", "")
    b = urlparse(url2).netloc.lower().replace("www.", "")
    return a == b


def detect_wordpress(html, response):
    text = html.decode("utf-8", errors="ignore").lower()

    indicators = []

    if "wordpress" in text:
        indicators.append("WordPress reference in HTML")

    if "/wp-content/" in text:
        indicators.append("/wp-content/ detected")

    if "/wp-includes/" in text:
        indicators.append("/wp-includes/ detected")

    if 'rel="https://api.w.org/"' in text:
        indicators.append("WordPress REST API link")

    if response:
        x_redirect = response.headers.get("x-redirect-by", "")
        if "wordpress" in x_redirect.lower():
            indicators.append("X-Redirect-By: WordPress")

    return len(indicators) > 0, indicators


def extract_wp_version(soup):
    generator = soup.find("meta", attrs={"name": re.compile("^generator$", re.I)})

    if generator:
        content = generator.get("content", "")

        match = re.search(
            r"WordPress\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
            content,
            re.I,
        )

        if match:
            return match.group(1)

    return None


def extract_theme_and_plugins(html):
    text = html.decode("utf-8", errors="ignore")

    themes = set()
    plugins = set()

    theme_matches = re.findall(
        r"/wp-content/themes/([^/\"'?]+)",
        text,
        re.I,
    )

    plugin_matches = re.findall(
        r"/wp-content/plugins/([^/\"'?]+)",
        text,
        re.I,
    )

    for item in theme_matches:
        themes.add(item)

    for item in plugin_matches:
        plugins.add(item)

    return sorted(themes), sorted(plugins)


def check_security_headers(response):
    expected = [
        "content-security-policy",
        "strict-transport-security",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "permissions-policy",
    ]

    headers = {
        k.lower(): v
        for k, v in response.headers.items()
    }

    missing = [
        h for h in expected
        if h not in headers
    ]

    return missing


def check_html(soup, base_url):
    findings = []

    title = soup.title.get_text(" ", strip=True) if soup.title else ""

    description_tag = soup.find(
        "meta",
        attrs={"name": re.compile("^description$", re.I)}
    )

    description = (
        description_tag.get("content", "").strip()
        if description_tag
        else ""
    )

    canonical = soup.find(
        "link",
        attrs={"rel": lambda value:
               value and "canonical" in value}
    )

    og_title = soup.find(
        "meta",
        attrs={"property": "og:title"}
    )

    og_description = soup.find(
        "meta",
        attrs={"property": "og:description"}
    )

    og_image = soup.find(
        "meta",
        attrs={"property": "og:image"}
    )

    h1s = soup.find_all("h1")

    images = soup.find_all("img")

    missing_alt = []

    for img in images:
        if not img.get("alt"):
            src = img.get("src", "")
            missing_alt.append(src[:150])

    if not title:
        findings.append(
            ("High", "Missing page title")
        )

    elif len(title) > 60:
        findings.append(
            ("Medium", f"Long page title ({len(title)} characters)")
        )

    if not description:
        findings.append(
            ("Medium", "Missing meta description")
        )

    if not canonical:
        findings.append(
            ("Low", "Canonical URL not detected")
        )

    if not og_title:
        findings.append(
            ("Low", "Open Graph title not detected")
        )

    if not og_description:
        findings.append(
            ("Low", "Open Graph description not detected")
        )

    if not og_image:
        findings.append(
            ("Low", "Open Graph image not detected")
        )

    if len(h1s) == 0:
        findings.append(
            ("Medium", "No H1 heading detected")
        )

    if len(h1s) > 1:
        findings.append(
            ("Low", f"Multiple H1 headings detected ({len(h1s)})")
        )

    if missing_alt:
        findings.append(
            (
                "Medium",
                f"{len(missing_alt)} image(s) without ALT text"
            )
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


def scan_special_endpoints(client, base_url):
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

        try:
            r = client.get(
                origin + path,
                follow_redirects=True,
                timeout=TIMEOUT,
            )

            results[name] = {
                "status": r.status_code,
                "accessible": r.status_code < 400,
            }

        except Exception:
            results[name] = {
                "status": None,
                "accessible": False,
            }

    return results


def check_internal_links(client, base_url, soup, limit=15):
    links = set()

    for a in soup.find_all("a", href=True):

        href = a["href"].strip()

        if href.startswith(("#", "mailto:", "tel:", "javascript:")):
            continue

        absolute = urljoin(base_url, href)

        if same_domain(base_url, absolute):
            links.add(absolute)

        if len(links) >= limit:
            break

    broken = []

    for link in links:

        try:
            r = client.get(
                link,
                follow_redirects=True,
                timeout=10,
            )

            if r.status_code >= 400:
                broken.append({
                    "url": link,
                    "status": r.status_code,
                })

        except Exception:
            broken.append({
                "url": link,
                "status": "error",
            })

    return broken


def calculate_score(data):
    score = 0

    if not data["wordpress"]:
        return 0

    wp_version = data.get("wp_version")

    if wp_version:
        try:
            major, minor = wp_version.split(".")[:2]
            version_number = float(f"{major}.{minor}")

            if version_number < 6.0:
                score += 25
            elif version_number < 6.5:
                score += 10

        except Exception:
            pass

    score += min(data["missing_alt_count"] * 2, 15)

    for severity, _ in data["findings"]:
        if severity == "High":
            score += 15
        elif severity == "Medium":
            score += 8
        else:
            score += 3

    security_missing = len(data.get("missing_security_headers", []))

    score += min(security_missing * 2, 12)

    special = data.get("special_endpoints", {})

    if special.get("readme", {}).get("accessible"):
        score += 5

    if special.get("license", {}).get("accessible"):
        score += 3

    return min(score, 100)


def scan_site(url):
    url = normalize_url(url)

    if not url:
        return {
            "url": "",
            "error": "Empty URL"
        }

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml",
    }

    with httpx.Client(
        headers=headers,
        verify=True,
    ) as client:

        response, html = fetch(client, url)

        if not response:
            return {
                "url": url,
                "error": "Could not connect"
            }

        final_url = str(response.url)

        soup = BeautifulSoup(
            html,
            "html.parser"
        )

        wordpress, indicators = detect_wordpress(
            html,
            response
        )

        wp_version = extract_wp_version(soup)

        themes, plugins = extract_theme_and_plugins(html)

        html_data = check_html(
            soup,
            final_url
        )

        missing_headers = check_security_headers(
            response
        )

        special = scan_special_endpoints(
            client,
            final_url
        )

        broken_links = check_internal_links(
            client,
            final_url,
            soup,
            limit=15
        )

        findings = list(html_data["findings"])

        if not wordpress:
            findings.append(
                (
                    "Info",
                    "WordPress could not be confirmed"
                )
            )

        if "http://" in url.lower() and final_url.startswith("https://"):
            pass

        if final_url.startswith("https://"):

            if missing_headers:
                findings.append(
                    (
                        "Low",
                        f"{len(missing_headers)} common security "
                        "header(s) missing"
                    )
                )

        if special["readme"]["accessible"]:
            findings.append(
                (
                    "Low",
                    "WordPress readme.html is publicly accessible"
                )
            )

        if special["license"]["accessible"]:
            findings.append(
                (
                    "Info",
                    "WordPress license.txt is publicly accessible"
                )
            )

        if special["xmlrpc"]["accessible"]:
            findings.append(
                (
                    "Info",
                    "XML-RPC endpoint responds publicly"
                )
            )

        for broken in broken_links:
            findings.append(
                (
                    "Medium",
                    f"Broken internal link ({broken['status']}): "
                    f"{broken['url']}"
                )
            )

        result = {
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
            "special_endpoints": special,
            "broken_links": broken_links,
            "findings": findings,
            "error": "",
        }

        result["lead_score"] = calculate_score(result)

        return result
