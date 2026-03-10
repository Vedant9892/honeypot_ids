"""HTTP SQL injection simulator for generating web attack telemetry."""

from __future__ import annotations

from urllib.parse import urlencode
from urllib.request import urlopen


def run_simulation(base_url: str = "http://127.0.0.1:8080") -> None:
    """Send a small set of SQL injection probes to the search endpoint."""
    payloads = [
        "' OR 1=1 --",
        "1 UNION SELECT username,password FROM users",
        "'; DROP TABLE sessions; --",
    ]
    for payload in payloads:
        query = urlencode({"q": payload})
        with urlopen(f"{base_url}/search?{query}") as response:
            response.read()


if __name__ == "__main__":
    run_simulation()
