"""Convert WiFi capture files (.pcap/.pcapng/.cap) into Hashcat mode 22000 hashes.

Uses hcxpcapngtool from the hcxtools package. The output of mode 22000 contains
both WPA-PMKID (lines starting with WPA*01*) and WPA-EAPOL (WPA*02*) hashes.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile

ALGO_MODE = 22000
HCXTOOL = "hcxpcapngtool"


class ConversionError(Exception):
    """Raised when the capture file cannot be converted."""


def is_available() -> bool:
    """Return True if hcxpcapngtool is installed and on PATH."""
    return shutil.which(HCXTOOL) is not None


def convert_to_hashes(pcap_path: str) -> tuple[list[str], str]:
    """Convert a capture file to a list of mode 22000 hash lines.

    Returns a tuple of (hashes, tool_stderr). Raises ConversionError when the
    tool is missing or fails to run.
    """
    if not is_available():
        raise ConversionError(
            f"{HCXTOOL} is not installed. Install the 'hcxtools' package."
        )

    with tempfile.TemporaryDirectory() as tmp:
        out_path = os.path.join(tmp, "out.hc22000")
        try:
            proc = subprocess.run(
                [HCXTOOL, "-o", out_path, pcap_path],
                capture_output=True,
                text=True,
                timeout=120,
            )
        except subprocess.TimeoutExpired as exc:
            raise ConversionError("Conversion timed out.") from exc

        stderr = (proc.stderr or "") + (proc.stdout or "")

        if not os.path.exists(out_path):
            # No hashes extracted (no valid handshake/PMKID found).
            return [], stderr

        with open(out_path, "r", encoding="utf-8", errors="ignore") as fh:
            hashes = [line.strip() for line in fh if line.strip()]

    # De-duplicate while preserving order.
    seen: set[str] = set()
    unique: list[str] = []
    for h in hashes:
        if h not in seen:
            seen.add(h)
            unique.append(h)
    return unique, stderr
