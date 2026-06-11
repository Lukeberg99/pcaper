"""Client for wpa-sec.stanev.org handshake uploads.

Uploads raw .pcap/.pcapng/.cap captures via HTTP POST with the user key in a
cookie. See https://wpa-sec.stanev.org/
"""
from __future__ import annotations

import io
import time

import requests

DEFAULT_URL = "https://wpa-sec.stanev.org"
UPLOAD_DELAY_SEC = 0.25


class StanevError(Exception):
    """Raised on API/transport errors."""

    def __init__(self, message: str, status: int | None = None, body: str = ""):
        super().__init__(message)
        self.status = status
        self.body = body


class StanevClient:
    def __init__(self, api_key: str, base_url: str = DEFAULT_URL, timeout: int = 60):
        if not api_key:
            raise StanevError("Missing Stanev API key.")
        self.api_key = api_key
        self.base_url = (base_url or DEFAULT_URL).rstrip("/")
        self.timeout = timeout

    def upload_pcap(self, data: bytes, filename: str) -> dict:
        """Upload one capture file. Returns status metadata for the UI."""
        cookies = {"key": self.api_key}
        files = {"file": (filename, io.BytesIO(data))}
        try:
            resp = requests.post(
                self.base_url,
                cookies=cookies,
                files=files,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise StanevError(f"Network error contacting Stanev: {exc}") from exc

        text = (resp.text or "").strip()
        if resp.status_code != 200:
            raise StanevError(
                text or f"Upload failed (HTTP {resp.status_code}).",
                status=resp.status_code,
                body=text,
            )

        already = "already submitted" in text.lower()
        return {
            "filename": filename,
            "status": "duplicate" if already else "accepted",
            "message": text or "OK",
        }

    def upload_many(self, items: list[tuple[str, bytes]]) -> list[dict]:
        """Upload multiple captures sequentially with a short delay between each."""
        results: list[dict] = []
        for index, (name, data) in enumerate(items):
            results.append(self.upload_pcap(data, name))
            if index < len(items) - 1:
                time.sleep(UPLOAD_DELAY_SEC)
        return results
