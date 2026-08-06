from __future__ import annotations

import socket


class WhoisClient:
    def __init__(self, *, timeout: float = 20.0, max_bytes: int = 8_000_000) -> None:
        self.timeout = timeout
        self.max_bytes = max_bytes

    def query(self, host: str, query: str, *, port: int = 43) -> str:
        chunks: list[bytes] = []
        total = 0
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                sock.settimeout(self.timeout)
                sock.sendall((query.rstrip("\r\n") + "\r\n").encode("utf-8"))
                while total < self.max_bytes:
                    chunk = sock.recv(min(65536, self.max_bytes - total))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
        except OSError as exc:
            raise RuntimeError(f"WHOIS request failed for {host}: {exc}") from exc
        return b"".join(chunks).decode("utf-8", errors="replace")
