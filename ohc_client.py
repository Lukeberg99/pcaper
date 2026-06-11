"""Minimal client for the OnlineHashCrack private API (v2).

Docs: https://api.onlinehashcrack.com/v2 (JSON over HTTPS, api_key in body).
"""
from __future__ import annotations

import requests

DEFAULT_URL = "https://api.onlinehashcrack.com/v2"
MAX_HASHES_PER_REQUEST = 50


class OHCError(Exception):
    """Raised on API/transport errors. Carries the parsed payload when available."""

    def __init__(self, message: str, payload: dict | None = None, status: int | None = None):
        super().__init__(message)
        self.payload = payload or {}
        self.status = status


class OHCClient:
    def __init__(self, api_key: str, base_url: str = DEFAULT_URL, timeout: int = 30):
        if not api_key:
            raise OHCError("Missing OHC_API_KEY. Set it in your environment / .env file.")
        self.api_key = api_key
        self.base_url = base_url or DEFAULT_URL
        self.timeout = timeout

    def _post(self, payload: dict) -> dict:
        body = {"api_key": self.api_key, "agree_terms": "yes", **payload}
        try:
            resp = requests.post(self.base_url, json=body, timeout=self.timeout)
        except requests.RequestException as exc:
            raise OHCError(f"Network error contacting OHC: {exc}") from exc

        try:
            data = resp.json()
        except ValueError:
            data = {}

        if resp.status_code == 429:
            retry = resp.headers.get("Retry-After") or data.get("retry_after")
            raise OHCError(
                f"Rate limit exceeded. Retry after {retry} seconds.",
                payload=data,
                status=429,
            )
        if not resp.ok:
            raise OHCError(
                data.get("message") or f"API error (HTTP {resp.status_code}).",
                payload=data,
                status=resp.status_code,
            )
        return data

    def add_tasks(self, hashes: list[str], algo_mode: int) -> dict:
        """Submit hashes. Caller must keep each batch <= 50 (chunk_and_submit handles it)."""
        return self._post(
            {"action": "add_tasks", "algo_mode": int(algo_mode), "hashes": hashes}
        )

    def list_tasks(self) -> dict:
        return self._post({"action": "list_tasks"})

    def chunk_and_submit(self, hashes: list[str], algo_mode: int) -> dict:
        """Submit hashes in batches of MAX_HASHES_PER_REQUEST and merge results."""
        merged = {
            "accepted": {"count": 0, "hashes": []},
            "skipped": {"count": 0, "hashes": [], "reason": ""},
            "rejected": {"count": 0, "hashes": [], "reason": ""},
            "request_ids": [],
            "success": True,
        }
        for i in range(0, len(hashes), MAX_HASHES_PER_REQUEST):
            batch = hashes[i : i + MAX_HASHES_PER_REQUEST]
            data = self.add_tasks(batch, algo_mode)
            for key in ("accepted", "skipped", "rejected"):
                section = data.get(key) or {}
                merged[key]["count"] += int(section.get("count", 0) or 0)
                merged[key]["hashes"].extend(section.get("hashes", []) or [])
                if section.get("reason"):
                    merged[key]["reason"] = section["reason"]
            if data.get("request_id"):
                merged["request_ids"].append(data["request_id"])
        return merged
