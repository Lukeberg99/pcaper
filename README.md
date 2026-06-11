---
title: PCAPER
emoji: 📡
colorFrom: blue
colorTo: indigo
sdk: docker
app_port: 7860
pinned: false
---

# PCAPER

A simple **Streamlit** app to upload WiFi handshake captures (`.pcap`,
`.pcapng`, `.cap`), convert them to Hashcat **mode 22000**
(WPA-PBKDF2-PMKID+EAPOL) hashes with
[`hcxpcapngtool`](https://github.com/ZerBea/hcxtools), and submit them
automatically to the [OnlineHashCrack](https://onlinehashcrack.com) private API
and/or [Stanev wpa-sec](https://wpa-sec.stanev.org/).

> Use is strictly limited to handshakes you own or are authorized to test.

## Features

- Upload **one or many** capture files at once (multi-select in the file picker).
- Choose destination: **OnlineHashCrack**, **Stanev (wpa-sec)**, or **Both**.
- OnlineHashCrack: server-side conversion to mode 22000 hashes (PMKID + EAPOL),
  de-duplicated, then submitted via `add_tasks` (batched at 50 hashes/request).
- Stanev: raw `.pcap` / `.pcapng` / `.cap` uploads to wpa-sec.stanev.org.
- Accepted / skipped / rejected metrics (OHC) and per-file upload status (Stanev).
- "My OHC tasks" tab listing your OnlineHashCrack tasks (`list_tasks`).
- **Each user enters their own API keys** in the sidebar (password fields). Keys
  are used only for that session's requests and are never stored, logged, or shared
  — so the app can run as a public, multi-user deployment.

## Deploy on Streamlit Community Cloud

1. Push this repo to GitHub (already done if you're reading this there).
2. Go to <https://share.streamlit.io/new>.
3. Pick this repo, branch `main`, main file `streamlit_app.py`.
4. Deploy. The `packages.txt` file makes Streamlit Cloud install `hcxtools`
   (which provides `hcxpcapngtool`) automatically.
5. Open the app and paste your API keys in the sidebar. No secrets config needed.

> Optional: for a single-user/private deploy, pre-fill keys under
> **Advanced settings → Secrets** (`OHC_API_KEY`, `STANEV_API_KEY`); they become
> the default sidebar values.

## Deploy on Hugging Face Spaces

This repo includes a `Dockerfile` (SDK: docker, port 7860). After pushing:

1. Create or open your Space and connect this repository.
2. Under **Settings → Repository secrets**, add optional defaults:
   - `OHC_API_KEY`
   - `STANEV_API_KEY`
3. Open the app and use the sidebar to choose **OnlineHashCrack**, **Stanev**, or **Both**, then select multiple `.pcap` files and submit once.

## Run locally

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# hcxpcapngtool (Debian/Ubuntu):
sudo apt-get install -y hcxtools   # macOS: brew install hcxtools

streamlit run streamlit_app.py
# then paste your sk_... key in the sidebar
```

## Configuration

No configuration is required — enter the API key in the UI. The following are
optional defaults (Streamlit secret or env var):

| Secret / env var   | Required | Description                                         |
|------------------|----------|-----------------------------------------------------|
| `OHC_API_KEY`    | no       | Pre-fills the OnlineHashCrack sidebar key.            |
| `STANEV_API_KEY` | no       | Pre-fills the Stanev (wpa-sec) sidebar key.         |
| `OHC_API_URL`    | no       | OHC API base endpoint (defaults to the v2 URL).     |
| `STANEV_API_URL` | no       | Stanev upload endpoint (defaults to wpa-sec URL).   |

## Notes

- Mode 22000 hashes are extracted only when the capture contains a valid PMKID
  or a complete EAPOL handshake. If none is found, nothing is submitted.
- The OHC API accepts up to 50 hashes per request; larger sets are chunked.
- Respect the API per-key hourly rate limit.
