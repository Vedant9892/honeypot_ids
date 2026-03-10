"""HTTP XSS probe simulator for the web honeypot."""

from __future__ import annotations

from urllib.parse import urlencode
from urllib.request import urlopen


def run_simulation(base_url: str = "http://127.0.0.1:8080") -> None:
    """Send reflective XSS-style probes to the search endpoint."""
    payloads = [
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(document.cookie)",
    ]
    for payload in payloads:
        query = urlencode({"q": payload})
        with urlopen(f"{base_url}/search?{query}") as response:
            response.read()


if __name__ == "__main__":
    run_simulation()
