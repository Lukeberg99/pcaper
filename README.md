---
title: PCAPER
emoji: 📡
colorFrom: blue
colorTo: indigo
sdk: streamlit
sdk_version: 1.40.0
app_file: streamlit_app.py
pinned: false
---

# PCAPER

A simple **Streamlit** app to upload WiFi handshake captures (`.pcap`,
`.pcapng`, `.cap`), convert them to Hashcat **mode 22000**
(WPA-PBKDF2-PMKID+EAPOL) hashes with
[`hcxpcapngtool`](https://github.com/ZerBea/hcxtools), and submit them
automatically to the [OnlineHashCrack](https://onlinehashcrack.com) private API.

> Use is strictly limited to handshakes you own or are authorized to test.

## Features

- Upload one or many capture files at once.
- Server-side conversion to mode 22000 hashes (PMKID + EAPOL), de-duplicated.
- Automatic submission to OHC (`add_tasks`), batched at 50 hashes/request.
- Accepted / skipped / rejected metrics plus `request_id`s.
- "My tasks" tab listing your OHC tasks (`list_tasks`).
- **Each user enters their own API key** in the sidebar (password field). The key
  is used only for that session's requests and is never stored, logged, or shared
  — so the app can run as a public, multi-user deployment.

## Deploy on Streamlit Community Cloud

1. Push this repo to GitHub (already done if you're reading this there).
2. Go to <https://share.streamlit.io/new>.
3. Pick this repo, branch `main`, main file `streamlit_app.py`.
4. Deploy. The `packages.txt` file makes Streamlit Cloud install `hcxtools`
   (which provides `hcxpcapngtool`) automatically.
5. Open the app and paste your `sk_...` key in the sidebar. No secrets config
   needed.

> Optional: if you'd rather pre-fill the key for a single-user/private deploy,
> set `OHC_API_KEY` under **Advanced settings → Secrets**; it just becomes the
> default value of the sidebar field.

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

| Secret / env var | Required | Description                                       |
|------------------|----------|---------------------------------------------------|
| `OHC_API_KEY`    | no       | Pre-fills the sidebar key field (single-user use). |
| `OHC_API_URL`    | no       | API base endpoint (defaults to the v2 URL).        |

## Notes

- Mode 22000 hashes are extracted only when the capture contains a valid PMKID
  or a complete EAPOL handshake. If none is found, nothing is submitted.
- The OHC API accepts up to 50 hashes per request; larger sets are chunked.
- Respect the API per-key hourly rate limit.
