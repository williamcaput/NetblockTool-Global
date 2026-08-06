from __future__ import annotations

import logging
import random
import time
from typing import Any

import httpx

LOG = logging.getLogger(__name__)


class HttpClient:
    """Small resilient HTTP client with bounded retries and exponential backoff."""

    def __init__(self, *, user_agent: str, timeout: float = 20.0, retries: int = 3) -> None:
        self.retries = max(0, retries)
        self.client = httpx.Client(
            timeout=httpx.Timeout(timeout),
            follow_redirects=True,
            headers={
                "User-Agent": user_agent,
                "Accept": "application/json, application/rdap+json;q=0.9, */*;q=0.1",
            },
        )

    def close(self) -> None:
        self.client.close()

    def __enter__(self) -> "HttpClient":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    def get_json(self, url: str, *, params: dict[str, Any] | None = None) -> dict[str, Any]:
        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            try:
                LOG.debug("GET %s params=%s", url, params)
                response = self.client.get(url, params=params)
                if response.status_code == 404:
                    return {}
                response.raise_for_status()
                payload = response.json()
                return payload if isinstance(payload, dict) else {}
            except (httpx.HTTPError, ValueError) as exc:
                last_error = exc
                if attempt >= self.retries:
                    break
                delay = min(8.0, (2**attempt) + random.random())
                LOG.debug("Request failed (%s); retrying in %.2fs", exc, delay)
                time.sleep(delay)
        raise RuntimeError(f"Request failed after {self.retries + 1} attempts: {url}: {last_error}")
