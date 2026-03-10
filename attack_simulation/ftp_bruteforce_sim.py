"""Simple FTP brute force simulator for the research honeypot."""

from __future__ import annotations

from ftplib import FTP, error_perm


def run_simulation(host: str = "127.0.0.1", port: int = 2121) -> None:
    """Attempt multiple FTP logins against the honeypot."""
    usernames = ["anonymous", "ftp", "admin"]
    passwords = ["guest", "guest123", "admin", "password"]

    for username in usernames:
        for password in passwords:
            client = FTP()
            try:
                client.connect(host=host, port=port, timeout=3)
                client.login(user=username, passwd=password)
                client.quit()
            except (OSError, error_perm):
                try:
                    client.close()
                except OSError:
                    pass


if __name__ == "__main__":
    run_simulation()
