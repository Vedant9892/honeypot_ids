"""Directory scanning simulator for generating reconnaissance traffic."""

from __future__ import annotations

from urllib.parse import urlencode
from urllib.error import HTTPError
from urllib.request import urlopen


def run_simulation(base_url: str = "http://127.0.0.1:8080") -> None:
    """Send a few common directory enumeration probes."""
    probes = [
        "../../etc/passwd",
        "/.git/config",
        "/wp-admin",
        "/phpmyadmin",
    ]
    for probe in probes:
        query = urlencode({"path": probe})
        try:
            with urlopen(f"{base_url}/admin?{query}") as response:
                response.read()
        except HTTPError:
            continue


if __name__ == "__main__":
    run_simulation()
