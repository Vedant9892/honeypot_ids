"""Simple SSH brute force traffic generator for local honeypot testing."""

from __future__ import annotations

import socket


def run_simulation(host: str = "127.0.0.1", port: int = 2222) -> None:
    """Send multiple fake SSH login attempts to the honeypot."""
    usernames = ["root", "admin", "ubuntu"]
    passwords = ["123456", "password", "toor", "admin123"]

    for username in usernames:
        for password in passwords:
            with socket.create_connection((host, port), timeout=3) as connection:
                try:
                    connection.recv(256)
                    connection.recv(256)
                    connection.sendall(f"{username}\n".encode("utf-8"))
                    connection.recv(256)
                    connection.sendall(f"{password}\n".encode("utf-8"))
                    connection.recv(256)
                except OSError:
                    continue


if __name__ == "__main__":
    run_simulation()
