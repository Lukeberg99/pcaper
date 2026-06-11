"""Client for wpa-sec.stanev.org handshake uploads and results.

Uploads raw .pcap/.pcapng/.cap captures via HTTP POST with the user key in a
cookie. Results can be fetched from the potfile export and the my_nets page.
See https://wpa-sec.stanev.org/
"""
from __future__ import annotations

import io
import re
import time

import requests

DEFAULT_URL = "https://wpa-sec.stanev.org"
UPLOAD_DELAY_SEC = 0.25
MAX_NET_PAGES = 20
_NET_ROW_RE = re.compile(
    r'<tr><td>.*?</td>'
    r'<td class="bssid">([^<]+)</td>'
    r'<td>([^<]*)</td>'
    r'<td>([^<]*)</td>'
    r'<td>([^<]*)</td>'
    r'<td>(.*?)</td>'
    r'<td>([^<]*)</td>'
    r'<td>([^<]*)</td>'
    r'<td>([^<]*)</td></tr>',
    re.DOTALL,
)
_PAGE_LINK_RE = re.compile(r'href=[\'"](\?my_nets(?:&page=\d+)?)[\'"]')


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

    def _get(self, path: str) -> requests.Response:
        cookies = {"key": self.api_key}
        url = f"{self.base_url.rstrip('/')}/{path.lstrip('/')}"
        try:
            resp = requests.get(url, cookies=cookies, timeout=self.timeout)
        except requests.RequestException as exc:
            raise StanevError(f"Network error contacting Stanev: {exc}") from exc
        if resp.status_code != 200:
            raise StanevError(
                f"Request failed (HTTP {resp.status_code}).",
                status=resp.status_code,
                body=(resp.text or "")[:500],
            )
        return resp

    @staticmethod
    def parse_potfile(text: str) -> list[dict]:
        """Parse Stanev potfile lines: bssid:client_mac:ssid:password."""
        rows: list[dict] = []
        seen: set[tuple[str, str, str]] = set()
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(":", 3)
            if len(parts) != 4:
                continue
            bssid, client_mac, ssid, password = parts
            dedupe_key = (bssid, ssid, password)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            rows.append(
                {
                    "bssid": bssid,
                    "client_mac": client_mac,
                    "ssid": ssid,
                    "password": password,
                }
            )
        return rows

    @staticmethod
    def parse_my_nets_html(html: str) -> list[dict]:
        """Parse the my_nets HTML table into structured rows."""
        rows: list[dict] = []
        for match in _NET_ROW_RE.finditer(html):
            bssid, ssid, net_type, features, key_cell, key_info, get_works, timestamp = (
                match.groups()
            )
            key_cell = key_cell.strip()
            if key_cell.startswith("<input"):
                password = ""
                status = "pending"
            else:
                password = key_cell
                status = "found"
            rows.append(
                {
                    "bssid": bssid,
                    "ssid": ssid,
                    "type": net_type,
                    "features": features,
                    "password": password,
                    "status": status,
                    "key_info": key_info,
                    "get_works": get_works,
                    "timestamp": timestamp,
                }
            )
        return rows

    @staticmethod
    def _page_paths(html: str) -> list[str]:
        paths = {"?my_nets"}
        for match in _PAGE_LINK_RE.finditer(html):
            paths.add(match.group(1))
        return sorted(paths, key=lambda path: int(path.split("page=")[-1]) if "page=" in path else 1)

    def download_founds(self) -> list[dict]:
        """Download cracked networks from ?api&dl=1."""
        resp = self._get("?api&dl=1")
        return self.parse_potfile(resp.text)

    def list_my_nets(self) -> list[dict]:
        """Fetch all my_nets pages and return submission status rows."""
        first = self._get("?my_nets")
        page_paths = self._page_paths(first.text)[:MAX_NET_PAGES]
        rows: list[dict] = []
        seen: set[tuple[str, str, str, str]] = set()

        for index, path in enumerate(page_paths):
            html = first.text if index == 0 else self._get(path).text
            for row in self.parse_my_nets_html(html):
                dedupe_key = (
                    row["bssid"],
                    row["ssid"],
                    row["type"],
                    row["timestamp"],
                )
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)
                rows.append(row)
        return rows
