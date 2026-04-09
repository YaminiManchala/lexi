import json
from urllib.parse import urlparse

import requests
from django.shortcuts import render

SCANNER_API_URL = "http://127.0.0.1:8001/scan"


def home(request):
    return render(request, "home.html")


def output_view(request):
    raw_url = (request.GET.get("url") or "").strip()

    if not raw_url:
        return render(
            request,
            "output.html",
            {
                "url": "",
                "data": None,
                "raw_json": "",
                "summary_cards": [],
                "error": "Please enter a website URL or domain name.",
            },
        )

    # Allow both domains and full URLs
    parsed = urlparse(raw_url)
    if not parsed.scheme:
        raw_url = "https://" + raw_url

    try:
        response = requests.get(
            SCANNER_API_URL,
            params={"url": raw_url},
            timeout=30,
        )
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.RequestException as exc:
        return render(
            request,
            "output.html",
            {
                "url": raw_url,
                "data": None,
                "raw_json": "",
                "summary_cards": [],
                "error": f"Scanner service error: {exc}",
            },
        )
    except ValueError:
        return render(
            request,
            "output.html",
            {
                "url": raw_url,
                "data": None,
                "raw_json": "",
                "summary_cards": [],
                "error": "Scanner returned invalid JSON.",
            },
        )

    summary_cards = []

    if isinstance(data, dict):
        key_map = [
            ("status", "Status"),
            ("target", "Target"),
            ("severity", "Severity"),
            ("risk", "Risk"),
            ("score", "Score"),
            ("message", "Message"),
        ]

        for key, label in key_map:
            value = data.get(key)
            if value not in (None, "", [], {}):
                summary_cards.append(
                    {
                        "label": label,
                        "value": value,
                    }
                )

        findings = data.get("findings") or data.get("vulnerabilities") or data.get("issues")
        if isinstance(findings, list):
            summary_cards.append(
                {
                    "label": "Findings",
                    "value": len(findings),
                }
            )

    raw_json = json.dumps(data, indent=2, ensure_ascii=False)

    return render(
        request,
        "output.html",
        {
            "url": raw_url,
            "data": data,
            "raw_json": raw_json,
            "summary_cards": summary_cards,
            "error": None,
        },
    )