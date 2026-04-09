from fastapi import FastAPI
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import requests

app = FastAPI()


# 1. SQL Injection

def test_sqli(url):
    payloads = ["' OR 1=1 --", "' OR 'a'='a"]
    for payload in payloads:
        test_url = f"{url}?id={payload}"
        try:
            res = requests.get(test_url, timeout=5)
            if any(err in res.text.lower() for err in ["sql", "syntax", "mysql", "error"]):
                return {"type": "SQL Injection", "severity": "High"}
        except:
            pass



# 2. Reflected XSS

def test_xss(url):
    payload = "<script>alert(1)</script>"
    test_url = f"{url}?q={payload}"
    res = requests.get(test_url)
    if payload in res.text:
        return {"type": "Reflected XSS", "severity": "High"}



# 3. Broken Authentication

def test_auth(url):
    endpoints = ["/admin", "/dashboard", "/api/admin"]

    for ep in endpoints:
        try:
            res = requests.get(url + ep, timeout=5)
            if res.status_code == 200:
                return {
                    "type": "Broken Authentication",
                    "severity": "Critical",
                    "detail": f"Accessed {ep} without login"
                }
        except:
            pass



# 4. Open Redirect

def test_redirect(url):
    payload = "http://evil.com"
    test_url = f"{url}?next={payload}"

    res = requests.get(test_url, allow_redirects=False)

    if "Location" in res.headers and payload in res.headers["Location"]:
        return {"type": "Open Redirect", "severity": "Medium"}



# 5. Security Misconfiguration

def test_headers(url):
    res = requests.get(url)
    headers = res.headers
    issues = []

    if "Content-Security-Policy" not in headers:
        issues.append("Missing CSP")
    if "X-Frame-Options" not in headers:
        issues.append("Clickjacking risk")
    if url.startswith("http://"):
        issues.append("No HTTPS")

    if issues:
        return {"type": "Security Misconfiguration", "severity": "Low", "issues": issues}

# MAIN SCAN API

def crawl(url):
    urls = [url]

    try:
        res = requests.get(url, timeout=5)
        soup = BeautifulSoup(res.text, "html.parser")

        for link in soup.find_all("a", href=True):
            full_url = urljoin(url, link["href"])

            if full_url.startswith("http") and full_url not in urls:
                urls.append(full_url)

    except:
        pass

    return urls[:5] 

from fastapi import FastAPI
import requests
from bs4 import BeautifulSoup

app = FastAPI()

# ---------------- CRAWLER ----------------
def crawl(url):
    visited = set()
    to_visit = [url]

    while to_visit and len(visited) < 10:
        current = to_visit.pop()

        if current in visited:
            continue

        visited.add(current)

        try:
            res = requests.get(current, timeout=5)
            soup = BeautifulSoup(res.text, "html.parser")

            for link in soup.find_all("a", href=True):
                href = link['href']
                if href.startswith("http"):
                    to_visit.append(href)

        except:
            pass

    return list(visited)


# ---------------- TESTS ----------------
def test_sqli(url):
    try:
        res = requests.get(f"{url}?id=' OR 1=1 --", timeout=5)
        if "sql" in res.text.lower():
            return {"type": "SQL Injection", "severity": "High"}
    except:
        pass


def test_xss(url):
    payload = "<script>alert(1)</script>"
    try:
        res = requests.get(f"{url}?q={payload}", timeout=5)
        if payload in res.text:
            return {"type": "XSS", "severity": "High"}
    except:
        pass


def test_auth(url):
    try:
        res = requests.get(url + "/admin", timeout=5)
        if res.status_code == 200:
            return {"type": "Broken Auth", "severity": "Critical"}
    except:
        pass


def test_redirect(url):
    try:
        res = requests.get(f"{url}?next=http://evil.com", allow_redirects=False)
        if "Location" in res.headers:
            return {"type": "Open Redirect", "severity": "Medium"}
    except:
        pass


def test_headers(url):
    try:
        res = requests.get(url)
        issues = []

        if "Content-Security-Policy" not in res.headers:
            issues.append("Missing CSP")

        if url.startswith("http://"):
            issues.append("No HTTPS")

        if issues:
            return {"type": "Misconfiguration", "severity": "Low", "issues": issues}
    except:
        pass


@app.get("/scan")
def scan(url: str):
    pages = crawl(url)
    results = []

    for page in pages:
        for test in [test_sqli, test_xss, test_auth, test_redirect, test_headers]:
            res = test(page)
            if res:
                res["url"] = page
                results.append(res)

    score = min(len(results) * 0.2, 1.0)

    return {
        "target": url,
        "pages_scanned": len(pages),
        "risk_score": score,
        "vulnerabilities": results
    }
